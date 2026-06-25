package scanner

import "testing"

// finding builds a minimal Finding for correlation tests.
func finding(name, reason, path string) Finding {
	return Finding{Name: name, Reason: reason, Path: path}
}

func hasTag(tags []string, want string) bool {
	for _, t := range tags {
		if t == want {
			return true
		}
	}
	return false
}

func mustCorrelations(t *testing.T, cfgs []CorrelationConfig) []Correlation {
	t.Helper()
	rules, err := CompileCorrelations(cfgs)
	if err != nil {
		t.Fatalf("CompileCorrelations: %v", err)
	}
	return rules
}

func TestCorrelatePairEmbedsAndDrops(t *testing.T) {
	rules := mustCorrelations(t, []CorrelationConfig{{
		ID:       "aws-credential-pair",
		Match:    FindingMatcher{NameRegex: "(?i)secret_access_key"},
		Partners: []FindingMatcher{{ReasonRegex: "gitleaks:aws-access-token"}},
	}})

	in := []Finding{
		finding("aws_access_key_id", "gitleaks:aws-access-token", "line:1"),
		finding("aws_secret_access_key", "high_entropy:4.9", "line:2"),
	}

	out := correlateFindings(in, rules)

	if len(out) != 1 {
		t.Fatalf("want 1 root finding, got %d", len(out))
	}
	primary := out[0]
	if primary.Name != "aws_secret_access_key" {
		t.Fatalf("primary should be the secret, got %q", primary.Name)
	}
	if !hasTag(primary.Tags, "aws-credential-pair") {
		t.Errorf("primary missing rule tag: %v", primary.Tags)
	}
	if len(primary.Correlated) != 1 {
		t.Fatalf("want 1 embedded secondary, got %d", len(primary.Correlated))
	}
	sec := primary.Correlated[0]
	if sec.Name != "aws_access_key_id" {
		t.Errorf("embedded secondary should be the access key id, got %q", sec.Name)
	}
	if !hasTag(sec.Tags, "aws-credential-pair") || !hasTag(sec.Tags, secondaryTag) {
		t.Errorf("secondary missing tags: %v", sec.Tags)
	}
}

func TestCorrelateThreePartSet(t *testing.T) {
	rules := mustCorrelations(t, []CorrelationConfig{{
		ID:    "oauth-client-bundle",
		Match: FindingMatcher{NameRegex: "(?i)client_secret"},
		Partners: []FindingMatcher{
			{NameRegex: "(?i)client_id"},
			{NameRegex: "(?i)tenant"},
		},
	}})

	in := []Finding{
		finding("client_id", "name", "line:1"),
		finding("tenant_id", "name", "line:2"),
		finding("client_secret", "name", "line:3"),
	}

	out := correlateFindings(in, rules)

	if len(out) != 1 {
		t.Fatalf("want 1 root finding, got %d", len(out))
	}
	if len(out[0].Correlated) != 2 {
		t.Fatalf("want 2 embedded secondaries, got %d", len(out[0].Correlated))
	}
}

func TestCorrelatePartnerOutsideWindow(t *testing.T) {
	rules := mustCorrelations(t, []CorrelationConfig{{
		ID:       "pair",
		Match:    FindingMatcher{NameRegex: "(?i)client_secret"},
		Partners: []FindingMatcher{{NameRegex: "(?i)client_id"}},
	}})

	// window for a 1-partner rule is minPrevWindow (3); separate the partner from
	// the primary by more than that so it falls out of the look-back window.
	in := []Finding{
		finding("client_id", "name", "line:1"),
		finding("noise1", "name", "line:2"),
		finding("noise2", "name", "line:3"),
		finding("noise3", "name", "line:4"),
		finding("client_secret", "name", "line:5"),
	}

	out := correlateFindings(in, rules)

	if len(out) != len(in) {
		t.Fatalf("partner outside window should not correlate; got %d roots", len(out))
	}
	for _, f := range out {
		if len(f.Correlated) != 0 {
			t.Errorf("unexpected correlation for %q", f.Name)
		}
	}
}

func TestCorrelateDistinctAssignment(t *testing.T) {
	// Two partner matchers that could both match the same single prior finding
	// must not be satisfied by it; each partner needs a distinct finding.
	rules := mustCorrelations(t, []CorrelationConfig{{
		ID:    "needs-two",
		Match: FindingMatcher{NameRegex: "(?i)secret"},
		Partners: []FindingMatcher{
			{NameRegex: "(?i)client"},
			{NameRegex: "(?i)client"},
		},
	}})

	in := []Finding{
		finding("client_id", "name", "line:1"),
		finding("secret", "name", "line:2"),
	}

	out := correlateFindings(in, rules)

	if len(out) != 2 {
		t.Fatalf("one prior cannot satisfy two partners; want 2 roots, got %d", len(out))
	}
}

func TestCorrelateExpressionForm(t *testing.T) {
	rules := mustCorrelations(t, []CorrelationConfig{{
		ID:  "aws-pair-expr",
		Tag: "aws-credential-pair",
		When: `current.name matches "(?i)secret_access_key" ` +
			`&& prev.reason == "gitleaks:aws-access-token"`,
	}})

	in := []Finding{
		finding("aws_access_key_id", "gitleaks:aws-access-token", "line:1"),
		finding("aws_secret_access_key", "high_entropy:4.9", "line:2"),
	}

	out := correlateFindings(in, rules)

	if len(out) != 1 {
		t.Fatalf("want 1 root finding, got %d", len(out))
	}
	if !hasTag(out[0].Tags, "aws-credential-pair") {
		t.Errorf("primary missing tag: %v", out[0].Tags)
	}
	if len(out[0].Correlated) != 1 {
		t.Fatalf("want 1 embedded secondary, got %d", len(out[0].Correlated))
	}
}

func TestCorrelateMatcherExpressionForm(t *testing.T) {
	// match and partner are each expr-lang predicates over a single finding.
	rules := mustCorrelations(t, []CorrelationConfig{{
		ID:       "expr-matcher-pair",
		Match:    FindingMatcher{Expr: `name matches "(?i)client_secret"`},
		Partners: []FindingMatcher{{Expr: `name matches "(?i)client_id" && value_length == 0`}},
	}})

	in := []Finding{
		finding("client_id", "name", "line:1"),
		finding("client_secret", "name", "line:2"),
	}

	out := correlateFindings(in, rules)

	if len(out) != 1 {
		t.Fatalf("want client_id folded into client_secret, got %d roots", len(out))
	}
	if len(out[0].Correlated) != 1 || out[0].Correlated[0].Name != "client_id" {
		t.Fatalf("expression matcher did not pair correctly: %+v", out[0].Correlated)
	}
}

func TestCompileFindingMatcherExprRegexConflict(t *testing.T) {
	_, err := CompileCorrelations([]CorrelationConfig{{
		ID:       "r",
		Match:    FindingMatcher{NameRegex: "x", Expr: `name == "x"`},
		Partners: []FindingMatcher{{NameRegex: "y"}},
	}})
	if err == nil {
		t.Fatal("want error when a matcher combines expr and regex fields")
	}
}

func TestCorrelateNoRulesPassthrough(t *testing.T) {
	in := []Finding{finding("a", "r", "line:1"), finding("b", "r", "line:2")}
	out := correlateFindings(in, nil)
	if len(out) != 2 {
		t.Fatalf("no rules should pass findings through unchanged, got %d", len(out))
	}
}

func TestBuiltinCorrelationsApplyWithoutConfig(t *testing.T) {
	// No user-configured correlations: the built-in oauth-client-credentials rule
	// should still pair client_secret with client_id.
	rules := mustCorrelations(t, nil)
	if len(rules) < len(builtinCorrelations) {
		t.Fatalf("built-in correlations missing: got %d rules", len(rules))
	}

	in := []Finding{
		finding("client_id", "name", "line:1"),
		finding("client_secret", "name", "line:2"),
	}

	out := correlateFindings(in, rules)

	if len(out) != 1 {
		t.Fatalf("want client_id folded into client_secret, got %d roots", len(out))
	}
	if !hasTag(out[0].Tags, "oauth-client-credentials") || len(out[0].Correlated) != 1 {
		t.Errorf("built-in pairing not applied: tags=%v correlated=%d", out[0].Tags, len(out[0].Correlated))
	}
}

func TestCompileCorrelationErrors(t *testing.T) {
	cases := []struct {
		name string
		cfg  CorrelationConfig
	}{
		{"no id or tag", CorrelationConfig{Match: FindingMatcher{NameRegex: "x"}, Partners: []FindingMatcher{{NameRegex: "y"}}}},
		{"structured without partners", CorrelationConfig{ID: "r", Match: FindingMatcher{NameRegex: "x"}}},
		{"empty matcher", CorrelationConfig{ID: "r", Match: FindingMatcher{}, Partners: []FindingMatcher{{NameRegex: "y"}}}},
		{"bad regex", CorrelationConfig{ID: "r", Match: FindingMatcher{NameRegex: "("}, Partners: []FindingMatcher{{NameRegex: "y"}}}},
		{"bad expression", CorrelationConfig{ID: "r", When: "current.nope +"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := CompileCorrelations([]CorrelationConfig{c.cfg}); err == nil {
				t.Fatalf("want error for %s", c.name)
			}
		})
	}
}

func TestPrevWindowGrowsToLargestRule(t *testing.T) {
	set := RuleSet{Correlations: mustCorrelations(t, []CorrelationConfig{{
		ID:    "big",
		Match: FindingMatcher{NameRegex: "x"},
		Partners: []FindingMatcher{
			{NameRegex: "a"}, {NameRegex: "b"}, {NameRegex: "c"}, {NameRegex: "d"},
		},
	}})}

	if got := set.prevWindow(); got != 4 {
		t.Fatalf("prevWindow want 4 (largest partners), got %d", got)
	}
}

func TestRecentFindings(t *testing.T) {
	in := []Finding{finding("a", "", ""), finding("b", "", ""), finding("c", "", ""), finding("d", "", "")}

	got := recentFindings(in, 2)
	if len(got) != 2 || got[0].Name != "c" || got[1].Name != "d" {
		t.Fatalf("want last two in order [c d], got %v", got)
	}
	if len(recentFindings(in, 10)) != 4 {
		t.Errorf("n larger than slice should return all")
	}
	if len(recentFindings(in, 0)) != 4 {
		t.Errorf("n<=0 should return all")
	}
}
