package llm

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/your-org/aegis-oracle/pkg/module"
)

type stubProvider struct {
	model string
	err   error
	calls *int
}

func (s stubProvider) CompleteJSON(context.Context, module.JSONRequest) (module.JSONResponse, error) {
	*s.calls++
	if s.err != nil {
		return module.JSONResponse{}, s.err
	}
	return module.JSONResponse{Content: `{"ok":true}`, Model: s.model}, nil
}

func TestFallbackProviderTriesNextOnQuotaError(t *testing.T) {
	firstCalls := 0
	secondCalls := 0
	p := &fallbackProvider{providers: []namedProvider{
		{name: "anthropic", provider: stubProvider{err: fmt.Errorf("anthropic: HTTP 400: credit balance is too low"), calls: &firstCalls}},
		{name: "openai", provider: stubProvider{model: "gpt-test", calls: &secondCalls}},
	}}

	resp, err := p.CompleteJSON(context.Background(), module.JSONRequest{})
	if err != nil {
		t.Fatalf("expected fallback success, got %v", err)
	}
	if resp.Model != "gpt-test" {
		t.Fatalf("expected openai fallback model, got %q", resp.Model)
	}
	if firstCalls != 1 || secondCalls != 1 {
		t.Fatalf("expected both providers called once, got first=%d second=%d", firstCalls, secondCalls)
	}
}

func TestFallbackProviderReturnsClearErrorWhenAllFail(t *testing.T) {
	firstCalls := 0
	secondCalls := 0
	p := &fallbackProvider{providers: []namedProvider{
		{name: "anthropic", provider: stubProvider{err: fmt.Errorf("anthropic: HTTP 429: rate limit"), calls: &firstCalls}},
		{name: "openai", provider: stubProvider{err: fmt.Errorf("openai: HTTP 401: invalid key"), calls: &secondCalls}},
	}}

	_, err := p.CompleteJSON(context.Background(), module.JSONRequest{})
	if err == nil {
		t.Fatal("expected error")
	}
	if got := err.Error(); got == "" || !containsAll(got, "LLM analysis could not be completed", "anthropic", "openai") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func containsAll(s string, needles ...string) bool {
	for _, n := range needles {
		if !strings.Contains(s, n) {
			return false
		}
	}
	return true
}
