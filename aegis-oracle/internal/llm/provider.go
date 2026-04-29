// Package llm provides the LLM provider abstraction and concrete
// implementations for Anthropic (Claude) and OpenAI (GPT).
//
// Both implementations enforce structured JSON output via the provider's
// native schema enforcement (Anthropic tool_use, OpenAI response_format).
// The module.LLMProvider interface is deliberately minimal so callers
// never import provider SDKs directly — only this package does.
package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/your-org/aegis-oracle/pkg/module"
)

// Config selects and configures the active provider(s).
type Config struct {
	Provider   string `yaml:"provider"`    // "anthropic" | "openai" | "auto"
	Anthropic  AnthropicConfig `yaml:"anthropic"`
	OpenAI     OpenAIConfig    `yaml:"openai"`
}

type AnthropicConfig struct {
	APIKey  string `yaml:"api_key"`   // or set ANTHROPIC_API_KEY
	Model   string `yaml:"model"`     // default: "claude-sonnet-4-5"
	BaseURL string `yaml:"base_url"`  // override for testing
}

type OpenAIConfig struct {
	APIKey  string `yaml:"api_key"`   // or set OPENAI_API_KEY
	Model   string `yaml:"model"`     // default: "gpt-4o"
	BaseURL string `yaml:"base_url"`
}

// New returns a provider from config. If provider == "auto" it prefers
// Anthropic when both keys are available.
func New(cfg Config) (module.LLMProvider, error) {
	switch strings.ToLower(cfg.Provider) {
	case "anthropic":
		return newAnthropic(cfg.Anthropic)
	case "openai":
		return newOpenAI(cfg.OpenAI)
	case "auto", "":
		if cfg.Anthropic.APIKey != "" {
			return newAnthropic(cfg.Anthropic)
		}
		if cfg.OpenAI.APIKey != "" {
			return newOpenAI(cfg.OpenAI)
		}
		return nil, fmt.Errorf("llm: no API key configured (set anthropic.api_key or openai.api_key)")
	default:
		return nil, fmt.Errorf("llm: unknown provider %q", cfg.Provider)
	}
}

// ─────────────────────────── Anthropic ─────────────────────────────────

type anthropicProvider struct {
	apiKey  string
	model   string
	baseURL string
	client  *http.Client
}

func newAnthropic(cfg AnthropicConfig) (*anthropicProvider, error) {
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("anthropic: api_key is required")
	}
	model := cfg.Model
	if model == "" {
		model = "claude-sonnet-4-5"
	}
	base := cfg.BaseURL
	if base == "" {
		base = "https://api.anthropic.com"
	}
	return &anthropicProvider{
		apiKey:  cfg.APIKey,
		model:   model,
		baseURL: strings.TrimRight(base, "/"),
		client:  &http.Client{Timeout: 120 * time.Second},
	}, nil
}

// CompleteJSON sends a structured-output request to Anthropic using
// tool_use to enforce the JSON schema. The response content is always
// the raw JSON matching the provided schema.
func (a *anthropicProvider) CompleteJSON(ctx context.Context, req module.JSONRequest) (module.JSONResponse, error) {
	model := req.Model
	if model == "" {
		model = a.model
	}
	maxTok := req.MaxTokens
	if maxTok == 0 {
		maxTok = 4096
	}

	// Wrap the caller's schema as an Anthropic tool definition.
	// By asking the model to call "produce_analysis", the response is
	// always structured JSON — no prose escapes.
	tool := map[string]any{
		"name":        "produce_analysis",
		"description": "Produce the structured analysis as defined by the input_schema.",
		"input_schema": req.Schema,
	}

	body := map[string]any{
		"model":      model,
		"max_tokens": maxTok,
		"system":     req.System,
		"messages": []map[string]any{
			{"role": "user", "content": req.User},
		},
		"tools":       []any{tool},
		"tool_choice": map[string]string{"type": "tool", "name": "produce_analysis"},
	}

	respBody, err := a.post(ctx, "/v1/messages", body)
	if err != nil {
		return module.JSONResponse{}, err
	}

	// Parse Anthropic response.
	var ar struct {
		Model      string `json:"model"`
		StopReason string `json:"stop_reason"`
		Usage      struct {
			InputTokens  int `json:"input_tokens"`
			OutputTokens int `json:"output_tokens"`
		} `json:"usage"`
		Content []struct {
			Type  string          `json:"type"`
			Input json.RawMessage `json:"input"`
		} `json:"content"`
	}
	if err := json.Unmarshal(respBody, &ar); err != nil {
		return module.JSONResponse{}, fmt.Errorf("decode anthropic response: %w", err)
	}

	var content string
	for _, block := range ar.Content {
		if block.Type == "tool_use" && len(block.Input) > 0 {
			content = string(block.Input)
			break
		}
	}
	if content == "" {
		return module.JSONResponse{}, fmt.Errorf("anthropic: no tool_use block in response (stop=%s)", ar.StopReason)
	}

	return module.JSONResponse{
		Content:    content,
		Model:      ar.Model,
		StopReason: ar.StopReason,
		TokenUsage: module.TokenUsage{
			Input:  ar.Usage.InputTokens,
			Output: ar.Usage.OutputTokens,
		},
	}, nil
}

func (a *anthropicProvider) post(ctx context.Context, path string, body any) ([]byte, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.baseURL+path, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", a.apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("anthropic: HTTP %d: %s", resp.StatusCode, rb)
	}
	return rb, nil
}

// ─────────────────────────── OpenAI ────────────────────────────────────

type openAIProvider struct {
	apiKey  string
	model   string
	baseURL string
	client  *http.Client
}

func newOpenAI(cfg OpenAIConfig) (*openAIProvider, error) {
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("openai: api_key is required")
	}
	model := cfg.Model
	if model == "" {
		model = "gpt-4o"
	}
	base := cfg.BaseURL
	if base == "" {
		base = "https://api.openai.com"
	}
	return &openAIProvider{
		apiKey:  cfg.APIKey,
		model:   model,
		baseURL: strings.TrimRight(base, "/"),
		client:  &http.Client{Timeout: 120 * time.Second},
	}, nil
}

// CompleteJSON sends a structured-output request to OpenAI using
// response_format: json_schema to enforce the schema.
func (o *openAIProvider) CompleteJSON(ctx context.Context, req module.JSONRequest) (module.JSONResponse, error) {
	model := req.Model
	if model == "" {
		model = o.model
	}
	maxTok := req.MaxTokens
	if maxTok == 0 {
		maxTok = 4096
	}

	messages := []map[string]any{}
	if req.System != "" {
		messages = append(messages, map[string]any{"role": "system", "content": req.System})
	}
	messages = append(messages, map[string]any{"role": "user", "content": req.User})

	body := map[string]any{
		"model":      model,
		"max_tokens": maxTok,
		"messages":   messages,
		"response_format": map[string]any{
			"type": "json_schema",
			"json_schema": map[string]any{
				"name":   "analysis",
				"strict": true,
				"schema": req.Schema,
			},
		},
	}

	respBody, err := o.post(ctx, "/v1/chat/completions", body)
	if err != nil {
		return module.JSONResponse{}, err
	}

	var or struct {
		Model   string `json:"model"`
		Choices []struct {
			FinishReason string `json:"finish_reason"`
			Message      struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Usage struct {
			PromptTokens     int `json:"prompt_tokens"`
			CompletionTokens int `json:"completion_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(respBody, &or); err != nil {
		return module.JSONResponse{}, fmt.Errorf("decode openai response: %w", err)
	}
	if len(or.Choices) == 0 {
		return module.JSONResponse{}, fmt.Errorf("openai: no choices in response")
	}

	return module.JSONResponse{
		Content:    or.Choices[0].Message.Content,
		Model:      or.Model,
		StopReason: or.Choices[0].FinishReason,
		TokenUsage: module.TokenUsage{
			Input:  or.Usage.PromptTokens,
			Output: or.Usage.CompletionTokens,
		},
	}, nil
}

func (o *openAIProvider) post(ctx context.Context, path string, body any) ([]byte, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.baseURL+path, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+o.apiKey)

	resp, err := o.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("openai: HTTP %d: %s", resp.StatusCode, rb)
	}
	return rb, nil
}
