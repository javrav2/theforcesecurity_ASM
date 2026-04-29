// Package knowledgebase loads and indexes the CWE profiles and dev
// patterns authored in /knowledgebase/*.yaml.
//
// The KB is the institutional memory that makes Phase A reasoning sharp.
// Profiles capture how a CWE class actually manifests in production code;
// patterns capture specific exploitable shapes with structured
// preconditions reusable across CVEs.
//
// Loading rules:
//   - Walk knowledgebase/cwe/*.yaml → CWEProfile records keyed by CWEID
//   - Walk knowledgebase/patterns/*.yaml → DevPattern records keyed by PatternID
//   - Validate required fields and known enum values
//   - Compute a content hash per file so the daemon can detect drift
//
// Loaders are read-only. Mutations to the KB happen via PR + filesystem.
package knowledgebase

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/your-org/aegis-oracle/pkg/schema"
)

// KB is the in-memory knowledge base. Construct via Load.
type KB struct {
	CWEProfiles map[string]Loaded[schema.CWEProfile]
	DevPatterns map[string]Loaded[schema.DevPattern]

	// Reverse indexes for fast Phase A enrichment lookups.
	patternsByCWE       map[string][]string // cwe_id -> []pattern_id
	patternsByEcosystem map[string][]string // ecosystem -> []pattern_id
}

// Loaded wraps a knowledge-base record with provenance metadata.
type Loaded[T any] struct {
	Record   T      `json:"record"`
	YAMLHash string `json:"yaml_hash"`
	Path     string `json:"path"`
}

// Load reads a knowledgebase root directory and returns a populated KB.
//
// Layout expected:
//
//	root/cwe/<CWE-ID>.yaml
//	root/patterns/<pattern.id>.yaml
//
// Missing subdirectories are tolerated (returns empty maps), but malformed
// YAML or missing required fields fail loudly with a wrapped error so the
// daemon refuses to start with a corrupt KB.
func Load(root string) (*KB, error) {
	kb := &KB{
		CWEProfiles:         make(map[string]Loaded[schema.CWEProfile]),
		DevPatterns:         make(map[string]Loaded[schema.DevPattern]),
		patternsByCWE:       make(map[string][]string),
		patternsByEcosystem: make(map[string][]string),
	}

	if err := loadDir(filepath.Join(root, "cwe"), kb.loadCWE); err != nil {
		return nil, fmt.Errorf("load cwe profiles: %w", err)
	}
	if err := loadDir(filepath.Join(root, "patterns"), kb.loadPattern); err != nil {
		return nil, fmt.Errorf("load dev patterns: %w", err)
	}
	kb.buildIndexes()
	return kb, nil
}

// PatternsForCWEs returns dev patterns whose cwe_ids intersect the given
// list, optionally filtered by ecosystem and framework. Used by the
// intrinsic reasoner to attach priors to a CVE before LLM call.
//
// An empty ecosystem matches all ecosystems; same for framework.
func (kb *KB) PatternsForCWEs(cwes []string, ecosystem, framework string) []schema.DevPattern {
	seen := make(map[string]struct{})
	out := make([]schema.DevPattern, 0)
	for _, cwe := range cwes {
		for _, pid := range kb.patternsByCWE[cwe] {
			if _, ok := seen[pid]; ok {
				continue
			}
			p := kb.DevPatterns[pid].Record
			if ecosystem != "" && !strings.EqualFold(p.Ecosystem, ecosystem) {
				continue
			}
			if framework != "" && p.Framework != "" && !strings.EqualFold(p.Framework, framework) {
				continue
			}
			seen[pid] = struct{}{}
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PatternID < out[j].PatternID })
	return out
}

// CWEsByID returns CWE profiles for the given CWE IDs that exist in the
// KB. Missing IDs are silently skipped — analysts can extend the KB
// later without breaking analyses today.
func (kb *KB) CWEsByID(ids []string) []schema.CWEProfile {
	out := make([]schema.CWEProfile, 0, len(ids))
	for _, id := range ids {
		if p, ok := kb.CWEProfiles[id]; ok {
			out = append(out, p.Record)
		}
	}
	return out
}

// Validate runs structural sanity checks across the loaded KB. Returns a
// joined error if any record is invalid, nil otherwise. Designed to be
// called from `aegis-oracle-cli kb validate` and from CI.
func (kb *KB) Validate() error {
	var errs []error
	for id, l := range kb.CWEProfiles {
		if err := validateCWE(l.Record); err != nil {
			errs = append(errs, fmt.Errorf("cwe %s (%s): %w", id, l.Path, err))
		}
	}
	for id, l := range kb.DevPatterns {
		if err := validatePattern(l.Record); err != nil {
			errs = append(errs, fmt.Errorf("pattern %s (%s): %w", id, l.Path, err))
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

// CWEProfile returns a single CWEProfile by ID (e.g. "CWE-22") and whether it exists.
func (kb *KB) CWEProfile(id string) (schema.CWEProfile, bool) {
	l, ok := kb.CWEProfiles[id]
	return l.Record, ok
}

// AllPatterns returns all loaded DevPattern records in unspecified order.
func (kb *KB) AllPatterns() []schema.DevPattern {
	out := make([]schema.DevPattern, 0, len(kb.DevPatterns))
	for _, l := range kb.DevPatterns {
		out = append(out, l.Record)
	}
	return out
}

// Stats returns counts useful for health checks and admin commands.
func (kb *KB) Stats() Stats {
	ecosystems := make(map[string]struct{})
	for _, l := range kb.DevPatterns {
		ecosystems[l.Record.Ecosystem] = struct{}{}
	}
	return Stats{
		CWEProfiles:    len(kb.CWEProfiles),
		DevPatterns:    len(kb.DevPatterns),
		EcosystemCount: len(ecosystems),
	}
}

type Stats struct {
	CWEProfiles    int `json:"cwe_profiles"`
	DevPatterns    int `json:"dev_patterns"`
	EcosystemCount int `json:"ecosystem_count"`
}

// ─────────────────────────── internal ──────────────────────────────────

func loadDir(dir string, handler func(path string, data []byte) error) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			continue
		}
		full := filepath.Join(dir, name)
		data, err := os.ReadFile(full)
		if err != nil {
			return fmt.Errorf("read %s: %w", full, err)
		}
		if err := handler(full, data); err != nil {
			return err
		}
	}
	return nil
}

func (kb *KB) loadCWE(path string, data []byte) error {
	var p schema.CWEProfile
	if err := yaml.Unmarshal(data, &p); err != nil {
		return fmt.Errorf("yaml %s: %w", path, err)
	}
	if p.CWEID == "" {
		return fmt.Errorf("%s: cwe_id is required", path)
	}
	if _, exists := kb.CWEProfiles[p.CWEID]; exists {
		return fmt.Errorf("%s: duplicate cwe_id %q", path, p.CWEID)
	}
	kb.CWEProfiles[p.CWEID] = Loaded[schema.CWEProfile]{
		Record:   p,
		YAMLHash: hashBytes(data),
		Path:     path,
	}
	return nil
}

func (kb *KB) loadPattern(path string, data []byte) error {
	var p schema.DevPattern
	if err := yaml.Unmarshal(data, &p); err != nil {
		return fmt.Errorf("yaml %s: %w", path, err)
	}
	if p.PatternID == "" {
		return fmt.Errorf("%s: pattern_id is required", path)
	}
	if _, exists := kb.DevPatterns[p.PatternID]; exists {
		return fmt.Errorf("%s: duplicate pattern_id %q", path, p.PatternID)
	}
	kb.DevPatterns[p.PatternID] = Loaded[schema.DevPattern]{
		Record:   p,
		YAMLHash: hashBytes(data),
		Path:     path,
	}
	return nil
}

func (kb *KB) buildIndexes() {
	for id, l := range kb.DevPatterns {
		for _, cwe := range l.Record.CWEIDs {
			kb.patternsByCWE[cwe] = append(kb.patternsByCWE[cwe], id)
		}
		kb.patternsByEcosystem[l.Record.Ecosystem] = append(kb.patternsByEcosystem[l.Record.Ecosystem], id)
	}
}

func hashBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func validateCWE(p schema.CWEProfile) error {
	switch p.Abstraction {
	case "class", "base", "variant", "compound":
	case "":
		return errors.New("abstraction is required")
	default:
		return fmt.Errorf("abstraction %q must be class|base|variant|compound", p.Abstraction)
	}
	if p.Name == "" {
		return errors.New("name is required")
	}
	for i, a := range p.ExploitArchetypes {
		if a.ArchetypeID == "" {
			return fmt.Errorf("exploit_archetypes[%d]: archetype_id is required", i)
		}
		if a.Summary == "" {
			return fmt.Errorf("exploit_archetypes[%d]: summary is required", i)
		}
	}
	return nil
}

func validatePattern(p schema.DevPattern) error {
	if p.PatternName == "" {
		return errors.New("pattern_name is required")
	}
	if p.Summary == "" {
		return errors.New("summary is required")
	}
	if len(p.CWEIDs) == 0 {
		return errors.New("cwe_ids must not be empty")
	}
	if p.Ecosystem == "" {
		return errors.New("ecosystem is required")
	}
	if len(p.ExploitPreconditions) == 0 {
		return errors.New("exploit_preconditions must not be empty")
	}
	for i, pre := range p.ExploitPreconditions {
		if pre.ID == "" {
			return fmt.Errorf("exploit_preconditions[%d]: id is required", i)
		}
		if pre.VerificationSignal == "" {
			return fmt.Errorf("exploit_preconditions[%d]: verification_signal is required", i)
		}
		switch pre.Severity {
		case schema.PreconditionBlocker, schema.PreconditionContributing:
		default:
			return fmt.Errorf("exploit_preconditions[%d]: severity %q must be blocker|contributing", i, pre.Severity)
		}
	}
	switch p.RemoteTriggerability {
	case "yes", "no", "conditional":
	default:
		return fmt.Errorf("remote_triggerability %q must be yes|no|conditional", p.RemoteTriggerability)
	}
	if p.Curator == "" {
		return errors.New("curator is required")
	}
	return nil
}
