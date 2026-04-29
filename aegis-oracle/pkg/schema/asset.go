package schema

import (
	"strconv"
	"strings"
	"time"
)

type Exposure string

const (
	ExposureInternet Exposure = "internet"
	ExposureInternal Exposure = "internal"
	ExposureIsolated Exposure = "isolated"
	ExposureUnknown  Exposure = "unknown"
)

type Criticality string

const (
	CriticalityCritical Criticality = "critical"
	CriticalityHigh     Criticality = "high"
	CriticalityMedium   Criticality = "medium"
	CriticalityLow      Criticality = "low"
	CriticalityUnknown  Criticality = "unknown"
)

// Asset is the bot's view of a single asset from the host ASM platform.
// The ASM is the source of truth; adapters populate this from inventory.
type Asset struct {
	ID          string       `json:"asset_id"`
	TenantID    string       `json:"tenant_id,omitempty"`
	Hostname    string       `json:"hostname,omitempty"`
	IP          string       `json:"ip,omitempty"`
	OpenPorts   []int        `json:"open_ports,omitempty"`
	Signals     AssetSignals `json:"signals"`
	Criticality Criticality  `json:"criticality"`
	Exposure    Exposure     `json:"exposure"`
	Source      string       `json:"source"`
	UpdatedAt   time.Time    `json:"updated_at"`
}

// AssetSignals is intentionally a flat bag with optional fields organized
// in tiers (Network/HTTP/TLS basic → tech stack → behavioral → deep).
// Phase B preconditions reference signal paths via dotted keys; missing =
// PreconditionUnknown. New tiers add new optional fields without breaking
// older signals.
type AssetSignals struct {
	Network *NetworkSignals `json:"network,omitempty"`
	HTTP    *HTTPSignals    `json:"http,omitempty"`
	TLS     *TLSSignals     `json:"tls,omitempty"`

	TechStack []TechComponent `json:"tech_stack,omitempty"`

	Auth *AuthSignals `json:"auth,omitempty"`

	RuntimeFlags map[string]string `json:"runtime_flags,omitempty"`
	Container    *ContainerSignals `json:"container,omitempty"`
	Tenant       *TenantSignals    `json:"tenant,omitempty"`
	FS           *FSSignals        `json:"fs,omitempty"`

	Extra map[string]string `json:"extra,omitempty"`
}

type NetworkSignals struct {
	InternetFacing *bool  `json:"internet_facing,omitempty"`
	OpenPorts      []int  `json:"open_ports,omitempty"`
	WAF            string `json:"waf,omitempty"`
}

type HTTPSignals struct {
	Headers      map[string]string `json:"headers,omitempty"`
	ServerBanner string            `json:"server_banner,omitempty"`
}

type TLSSignals struct {
	Subject string `json:"subject,omitempty"`
	Issuer  string `json:"issuer,omitempty"`
}

type TechComponent struct {
	Name       string  `json:"name"`
	Version    string  `json:"version,omitempty"`
	Confidence float64 `json:"confidence,omitempty"`
}

type AuthSignals struct {
	Required *bool  `json:"required,omitempty"`
	Method   string `json:"method,omitempty"`
}

type ContainerSignals struct {
	StartupArgs []string `json:"startup_args,omitempty"`
	Image       string   `json:"image,omitempty"`
}

type TenantSignals struct {
	RunsUserCode *bool  `json:"runs_user_code,omitempty"`
	SandboxKind  string `json:"sandbox_kind,omitempty"`
}

type FSSignals struct {
	WritablePaths []string `json:"writable_paths,omitempty"`
}

// Lookup resolves a dotted signal path against the asset signals.
// Returns (value, true) when present, ("", false) when missing.
//
// Supported paths:
//
//	network.internet_facing | network.waf
//	auth.required | auth.method
//	tech_stack.<name> | tech_stack.<name>.version
//	runtime_flags.<key>
//	container.startup_args | container.image
//	tenant.runs_user_code | tenant.sandbox_kind
//	fs.writable_paths
//	extra.<key>
//
// New signals: extend the switch below alongside the corresponding struct
// field. Keep the canonical path list in sync with prompts/v1.go.
func (s AssetSignals) Lookup(path string) (string, bool) {
	parts := strings.SplitN(path, ".", 2)
	if len(parts) < 2 {
		return "", false
	}
	head, tail := parts[0], parts[1]

	switch head {
	case "runtime_flags":
		if v, ok := s.RuntimeFlags[tail]; ok {
			return v, true
		}
	case "tenant":
		if s.Tenant == nil {
			return "", false
		}
		switch tail {
		case "runs_user_code":
			if s.Tenant.RunsUserCode != nil {
				return strconv.FormatBool(*s.Tenant.RunsUserCode), true
			}
		case "sandbox_kind":
			if s.Tenant.SandboxKind != "" {
				return s.Tenant.SandboxKind, true
			}
		}
	case "auth":
		if s.Auth == nil {
			return "", false
		}
		switch tail {
		case "required":
			if s.Auth.Required != nil {
				return strconv.FormatBool(*s.Auth.Required), true
			}
		case "method":
			if s.Auth.Method != "" {
				return s.Auth.Method, true
			}
		}
	case "network":
		if s.Network == nil {
			return "", false
		}
		switch tail {
		case "internet_facing":
			if s.Network.InternetFacing != nil {
				return strconv.FormatBool(*s.Network.InternetFacing), true
			}
		case "waf":
			if s.Network.WAF != "" {
				return s.Network.WAF, true
			}
		}
	case "container":
		if s.Container == nil {
			return "", false
		}
		switch tail {
		case "startup_args":
			if len(s.Container.StartupArgs) > 0 {
				return strings.Join(s.Container.StartupArgs, " "), true
			}
		case "image":
			if s.Container.Image != "" {
				return s.Container.Image, true
			}
		}
	case "fs":
		if s.FS == nil {
			return "", false
		}
		if tail == "writable_paths" && len(s.FS.WritablePaths) > 0 {
			return strings.Join(s.FS.WritablePaths, ","), true
		}
	case "tech_stack":
		// Two valid forms: "tech_stack.<name>" → version, or
		// "tech_stack.<name>.version".
		name, sub, _ := strings.Cut(tail, ".")
		for _, t := range s.TechStack {
			if !strings.EqualFold(t.Name, name) {
				continue
			}
			if sub == "" || sub == "version" {
				if t.Version != "" {
					return t.Version, true
				}
			}
		}
	case "extra":
		if v, ok := s.Extra[tail]; ok {
			return v, true
		}
	}
	return "", false
}
