package enrichers

import (
	"testing"
	"time"

	"github.com/your-org/aegis-oracle/pkg/schema"
)

func TestCVEYear(t *testing.T) {
	tests := []struct {
		in      string
		want    string
		wantOK  bool
	}{
		{"CVE-2021-44228", "2021", true},
		{"cve-2024-1234", "2024", true},
		{"CVE-99-1", "", false},
		{"not-a-cve", "", false},
		{"", "", false},
	}
	for _, tc := range tests {
		got, ok := cveYear(tc.in)
		if ok != tc.wantOK || got != tc.want {
			t.Fatalf("cveYear(%q) = (%q, %v); want (%q, %v)", tc.in, got, ok, tc.want, tc.wantOK)
		}
	}
}

func TestApplyPoCGitHubSetsEvidence(t *testing.T) {
	newest := time.Now().UTC().Add(-5 * 24 * time.Hour).Format(time.RFC3339)
	ext := ExternalEnrichment{
		PoCGitHub: PoCGitHubResult{
			Found:         true,
			POCCount:      3,
			RecentPOCDays: 5,
			NewestPOCAt:   newest,
			POCs: []PoCGitHubRepo{
				{URL: "https://github.com/example/poc-a", Stars: 10, CreatedAt: newest},
				{URL: "https://github.com/example/poc-b", Stars: 2, CreatedAt: newest},
			},
		},
	}
	var ev schema.ExploitationEvidence
	Apply(ext, &ev)

	if !ev.PublicPOCFound {
		t.Fatal("expected PublicPOCFound")
	}
	if ev.PublicPOCCount != 3 {
		t.Fatalf("PublicPOCCount=%d; want 3", ev.PublicPOCCount)
	}
	if ev.RecentPOCDays != 5 {
		t.Fatalf("RecentPOCDays=%d; want 5", ev.RecentPOCDays)
	}
	if len(ev.PublicPOCURLs) != 2 {
		t.Fatalf("PublicPOCURLs len=%d; want 2", len(ev.PublicPOCURLs))
	}
}
