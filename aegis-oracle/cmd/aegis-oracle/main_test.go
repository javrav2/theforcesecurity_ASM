package main

import (
	"testing"
	"time"

	"github.com/your-org/aegis-oracle/internal/modules/reasoners/priority/opes"
	"github.com/your-org/aegis-oracle/pkg/schema"
)

func TestAnalyzeGenericFindingClassifiesAnonymousMongoRansomware(t *testing.T) {
	asset := publicAsset("asset-mongo", 27017)
	vuln := schema.GenericVulnerability{
		ID:          "vuln-1",
		Title:       "MongoDB Exposed Without Authentication",
		Severity:    "critical",
		DetectedBy:  "port_scanner",
		Evidence:    "READ_ME_TO_RECOVER_YOUR_DATA database contains bitcoin ransom demand",
		Tags:        []string{"database", "mongodb"},
		Metadata:    map[string]any{"port": 27017, "service": "mongodb"},
		Remediation: "Restrict MongoDB to trusted networks and enforce authentication.",
	}

	result := analyzeGenericFinding(vuln, asset, opes.Config{})
	if result.FindingClass != "exposed_datastore" {
		t.Fatalf("expected exposed_datastore, got %q", result.FindingClass)
	}
	if result.OPES.Category != schema.PriorityCritical {
		t.Fatalf("expected ransomware marker to drive critical, got %+v", result.OPES)
	}
	if result.AnalystBrief.Title == "" || result.RecommendationText == "" {
		t.Fatalf("expected analyst brief and recommendation, got %+v", result)
	}
}

func TestAnalyzeGenericFindingClassifiesLeakedSecret(t *testing.T) {
	asset := publicAsset("asset-func", 443)
	vuln := schema.GenericVulnerability{
		ID:          "vuln-2",
		Title:       "Azure Function Exposes Environment Secrets",
		Severity:    "critical",
		DetectedBy:  "agent",
		Evidence:    "AzureWebJobsStorage AccountKey and Cosmos DB key disclosed by /api/Tester",
		Tags:        []string{"secret-leak", "azure"},
		Metadata:    map[string]any{"verified": true, "kind": "azure_function_env_dump"},
		Remediation: "Remove the endpoint and rotate exposed keys.",
	}

	result := analyzeGenericFinding(vuln, asset, opes.Config{})
	if result.FindingClass != "leaked_secret" {
		t.Fatalf("expected leaked_secret, got %q", result.FindingClass)
	}
	if result.AttackPathClass != schema.AttackPathValidCredentials {
		t.Fatalf("expected valid-credentials attack path, got %q", result.AttackPathClass)
	}
	if result.OPES.Value <= 0 {
		t.Fatalf("expected non-zero OPES score, got %+v", result.OPES)
	}
}

func publicAsset(id string, ports ...int) *schema.Asset {
	internet := true
	return &schema.Asset{
		ID:          id,
		Hostname:    id + ".example.test",
		OpenPorts:   ports,
		Criticality: schema.CriticalityHigh,
		Exposure:    schema.ExposureInternet,
		Source:      "test",
		UpdatedAt:   time.Now().UTC(),
		Signals: schema.AssetSignals{
			Network: &schema.NetworkSignals{
				InternetFacing: &internet,
				OpenPorts:      ports,
			},
			Extra: map[string]string{"secret_verified": "true"},
		},
	}
}
