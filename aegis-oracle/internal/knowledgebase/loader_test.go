package knowledgebase

import (
	"path/filepath"
	"testing"
)

// TestLoadGoldenKB loads the project-shipped knowledge base and verifies
// the canonical CWE-22 + nodejs.permissions-symlink-escape records are
// indexed and pass validation. This guards against KB drift breaking the
// rest of the pipeline.
func TestLoadGoldenKB(t *testing.T) {
	root, err := filepath.Abs("../../knowledgebase")
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	kb, err := Load(root)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if err := kb.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	if _, ok := kb.CWEProfiles["CWE-22"]; !ok {
		t.Errorf("CWE-22 missing from KB")
	}
	if _, ok := kb.CWEProfiles["CWE-59"]; !ok {
		t.Errorf("CWE-59 missing from KB")
	}
	pat, ok := kb.DevPatterns["nodejs.permissions-symlink-escape"]
	if !ok {
		t.Fatalf("pattern nodejs.permissions-symlink-escape missing from KB")
	}
	if pat.Record.RemoteTriggerability != "no" {
		t.Errorf("pattern remote_triggerability: got %q want no", pat.Record.RemoteTriggerability)
	}
	if len(pat.Record.ExploitPreconditions) < 2 {
		t.Errorf("pattern preconditions: got %d want >= 2", len(pat.Record.ExploitPreconditions))
	}

	matches := kb.PatternsForCWEs([]string{"CWE-22", "CWE-59"}, "nodejs", "")
	if len(matches) == 0 {
		t.Errorf("expected at least one nodejs pattern matching CWE-22/59, got 0")
	}
	for _, m := range matches {
		if m.Ecosystem != "nodejs" {
			t.Errorf("ecosystem filter failed: got %q in result", m.Ecosystem)
		}
	}

	stats := kb.Stats()
	if stats.CWEProfiles < 2 {
		t.Errorf("stats.CWEProfiles: got %d want >= 2", stats.CWEProfiles)
	}
	if stats.DevPatterns < 1 {
		t.Errorf("stats.DevPatterns: got %d want >= 1", stats.DevPatterns)
	}
}
