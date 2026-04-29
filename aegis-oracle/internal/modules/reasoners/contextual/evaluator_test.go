package contextual

import (
	"testing"

	"github.com/your-org/aegis-oracle/pkg/schema"
)

func TestEvaluate_UnknownWhenSignalMissing(t *testing.T) {
	intrinsic := &schema.IntrinsicAnalysis{
		Preconditions: []schema.Precondition{
			{
				ID:                 "node-permissions-active",
				VerificationSignal: "runtime_flags.node",
				MatchKind:          "regex",
				MatchValue:         "(--experimental-permissions|--permissions)",
				Severity:           schema.PreconditionBlocker,
			},
		},
	}
	asset := &schema.Asset{}
	out := Evaluate(intrinsic, asset)
	if len(out) != 1 {
		t.Fatalf("got %d evals", len(out))
	}
	if out[0].Status != schema.PreconditionUnknown {
		t.Errorf("expected Unknown, got %s", out[0].Status)
	}
}

func TestEvaluate_SatisfiedAndUnsatisfied(t *testing.T) {
	yes := true
	intrinsic := &schema.IntrinsicAnalysis{
		Preconditions: []schema.Precondition{
			{
				ID:                 "tenant-runs-user-code",
				VerificationSignal: "tenant.runs_user_code",
				MatchKind:          "equals",
				MatchValue:         "true",
				Severity:           schema.PreconditionBlocker,
			},
			{
				ID:                 "auth-bypass-needed",
				VerificationSignal: "auth.required",
				MatchKind:          "equals",
				MatchValue:         "false",
				Severity:           schema.PreconditionContributing,
			},
		},
	}
	authReq := true
	asset := &schema.Asset{
		Signals: schema.AssetSignals{
			Tenant: &schema.TenantSignals{RunsUserCode: &yes},
			Auth:   &schema.AuthSignals{Required: &authReq},
		},
	}
	out := Evaluate(intrinsic, asset)
	if out[0].Status != schema.PreconditionSatisfied {
		t.Errorf("first eval: expected Satisfied, got %s (%s)", out[0].Status, out[0].Reason)
	}
	if out[1].Status != schema.PreconditionUnsatisfied {
		t.Errorf("second eval: expected Unsatisfied, got %s (%s)", out[1].Status, out[1].Reason)
	}
}

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.2.3", "1.2.3", 0},
		{"1.2.3", "1.2.10", -1},
		{"1.2.10", "1.2.3", 1},
		{"v24.10.0", "24.10.0", 0},
		{"24.10.1", "24.10.0", 1},
	}
	for _, c := range cases {
		got := compareVersions(c.a, c.b)
		// Normalise to -1/0/1.
		if got > 0 {
			got = 1
		} else if got < 0 {
			got = -1
		}
		if got != c.want {
			t.Errorf("compareVersions(%q,%q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}
