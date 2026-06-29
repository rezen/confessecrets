package scanner

import (
	"strings"
	"testing"
)

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

func TestCorrelateDropsFileFromEmbeddedPartner(t *testing.T) {
	rules := mustCorrelations(t, []CorrelationConfig{{
		ID:       "aws-credential-pair",
		Match:    FindingMatcher{NameRegex: "(?i)secret_access_key"},
		Partners: []FindingMatcher{{ReasonRegex: "gitleaks:aws-access-token"}},
	}})

	in := []Finding{
		{Name: "aws_access_key_id", Reason: "gitleaks:aws-access-token", Path: "line:1", File: "creds.env"},
		{Name: "aws_secret_access_key", Reason: "high_entropy:4.9", Path: "line:2", File: "creds.env"},
	}

	out := correlateFindings(in, rules)

	if len(out) != 1 {
		t.Fatalf("want 1 root finding, got %d", len(out))
	}
	if out[0].File != "creds.env" {
		t.Errorf("primary File = %q, want creds.env retained", out[0].File)
	}
	if len(out[0].Correlated) != 1 {
		t.Fatalf("want 1 embedded secondary, got %d", len(out[0].Correlated))
	}
	if got := out[0].Correlated[0].File; got != "" {
		t.Errorf("embedded partner File = %q, want empty (dropped)", got)
	}
	if out[0].Correlated[0].Path != "line:1" {
		t.Errorf("embedded partner Path = %q, want line:1 retained", out[0].Correlated[0].Path)
	}
}

func TestCorrelateEnrichesPrimaryMeta(t *testing.T) {
	rules := mustCorrelations(t, []CorrelationConfig{{
		ID:    "oauth-client-bundle",
		Match: FindingMatcher{NameRegex: "(?i)client_secret"},
		Partners: []FindingMatcher{
			{NameRegex: "(?i)client_id"},
			{NameRegex: "(?i)username"},
		},
	}})

	in := []Finding{
		{Name: "client_id", Reason: "name", Path: "line:1", RawValue: "abc-123", Value: "ab***23"},
		{Name: "username", Reason: "name", Path: "line:2", RawValue: "svc-account", Value: "sv***nt"},
		{Name: "client_secret", Reason: "name", Path: "line:3", RawValue: "topsecret", Value: "to***et"},
	}

	out := correlateFindings(in, rules)

	if len(out) != 1 {
		t.Fatalf("want 1 root finding, got %d", len(out))
	}
	meta := out[0].Meta
	if meta == nil {
		t.Fatal("expected primary Meta to be populated from partners")
	}
	if meta.ClientID != "abc-123" {
		t.Errorf("ClientID = %q, want abc-123 (partner raw value)", meta.ClientID)
	}
	if meta.Username != "svc-account" {
		t.Errorf("Username = %q, want svc-account (partner raw value)", meta.Username)
	}
}

func TestCorrelateEnrichesURLFromPartner(t *testing.T) {
	// The built-in function-url rule folds a URL partner into the function key;
	// the partner's URL should land in the primary's Meta.URL.
	rules := mustCorrelations(t, nil)

	in := []Finding{
		{Name: "BASE_URL", Reason: "name", Path: "line:2", RawValue: "https://example-api.azurewebsites.net/api/inventory/search"},
		{Name: "FUNCTION_KEY", Reason: "name", Path: "line:3", RawValue: "6v-abm...", Value: "6v***=="},
	}

	out := correlateFindings(in, rules)

	if len(out) != 1 {
		t.Fatalf("want BASE_URL folded into FUNCTION_KEY, got %d roots", len(out))
	}
	meta := out[0].Meta
	if meta == nil || meta.URL != "https://example-api.azurewebsites.net/api/inventory/search" {
		t.Fatalf("want primary Meta.URL set from partner, got %+v", meta)
	}
}

func TestCorrelateEnrichesURLFromInfoReason(t *testing.T) {
	// A partner identified as a URL only by its info: reason still fills Meta.URL.
	rules := mustCorrelations(t, nil)

	in := []Finding{
		{Name: "endpoint", Reason: "info:azure-app-service", Path: "line:1", RawValue: "https://svc.example.com"},
		{Name: "client_secret", Reason: "name", Path: "line:2", RawValue: "topsecret", Value: "to***et"},
	}

	out := correlateFindings(in, rules)

	if len(out) != 1 {
		t.Fatalf("want endpoint folded into client_secret, got %d roots", len(out))
	}
	if meta := out[0].Meta; meta == nil || meta.URL != "https://svc.example.com" {
		t.Fatalf("want primary Meta.URL from info-URL partner, got %+v", meta)
	}
}

func TestCorrelateEnrichDoesNotOverwriteValueDerived(t *testing.T) {
	rules := mustCorrelations(t, []CorrelationConfig{{
		ID:       "oauth-client-bundle",
		Match:    FindingMatcher{NameRegex: "(?i)client_secret"},
		Partners: []FindingMatcher{{NameRegex: "(?i)client_id"}},
	}})

	// Primary already carries a value-derived ClientID; the partner must not clobber it.
	in := []Finding{
		{Name: "client_id", Reason: "name", Path: "line:1", RawValue: "partner-id"},
		{Name: "client_secret", Reason: "name", Path: "line:2", Meta: &Meta{ClientID: "value-derived-id"}},
	}

	out := correlateFindings(in, rules)

	if len(out) != 1 {
		t.Fatalf("want 1 root finding, got %d", len(out))
	}
	if got := out[0].Meta.ClientID; got != "value-derived-id" {
		t.Errorf("ClientID = %q, want value-derived-id preserved", got)
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

func TestCorrelateExpressionBareCurrentFields(t *testing.T) {
	// A when-expression may reference the current finding's fields directly (bare
	// `name`), the same way a filter expression does, alongside `prev`.
	rules := mustCorrelations(t, []CorrelationConfig{{
		ID:   "function-url-expr",
		When: `name contains "function" && prev.name contains "url"`,
	}})

	in := []Finding{
		finding("api_url", "name", "line:1"),
		finding("handler_function", "name", "line:2"),
	}

	out := correlateFindings(in, rules)

	if len(out) != 1 {
		t.Fatalf("want url folded into function, got %d roots", len(out))
	}
	if len(out[0].Correlated) != 1 || out[0].Correlated[0].Name != "api_url" {
		t.Fatalf("bare-name correlation did not pair correctly: %+v", out[0].Correlated)
	}
}

func TestBuiltinFunctionURLCorrelation(t *testing.T) {
	rules := mustCorrelations(t, nil)

	in := []Finding{
		finding("function_url", "info:aws-lambda-url", "line:1"),
		finding("lambda_function", "name", "line:2"),
	}

	out := correlateFindings(in, rules)

	if len(out) != 1 {
		t.Fatalf("want function_url folded into lambda_function, got %d roots", len(out))
	}
	if !hasTag(out[0].Tags, "function-url") || len(out[0].Correlated) != 1 {
		t.Errorf("built-in function-url pairing not applied: tags=%v correlated=%d", out[0].Tags, len(out[0].Correlated))
	}
}

func TestBuiltinClientSecretURLCorrelation(t *testing.T) {
	rules := mustCorrelations(t, nil)

	// A URL identified by name folds into the client_secret.
	in := []Finding{
		finding("token_url", "name", "line:1"),
		finding("client_secret", "name", "line:2"),
	}
	out := correlateFindings(in, rules)
	if len(out) != 1 {
		t.Fatalf("want token_url folded into client_secret, got %d roots", len(out))
	}
	if !hasTag(out[0].Tags, "client-secret-url") || len(out[0].Correlated) != 1 {
		t.Errorf("client-secret-url pairing not applied: tags=%v correlated=%d", out[0].Tags, len(out[0].Correlated))
	}

	// A URL identified only by its info: reason (a service endpoint) also folds in.
	in = []Finding{
		finding("BASE_URL", "info:azure-app-service", "line:1"),
		finding("CLIENT_SECRET", "name", "line:2"),
	}
	out = correlateFindings(in, rules)
	if len(out) != 1 || len(out[0].Correlated) != 1 || out[0].Correlated[0].Name != "BASE_URL" {
		t.Fatalf("info-URL did not fold into client_secret: %+v", out)
	}
}

func TestClientIDWinsOverURLForClientSecret(t *testing.T) {
	// When both a client_id and a URL precede a client_secret, the canonical
	// oauth-client-credentials pairing (listed first) claims the primary, so the
	// client_id is folded in rather than the URL.
	rules := mustCorrelations(t, nil)

	in := []Finding{
		finding("token_url", "name", "line:1"),
		finding("client_id", "name", "line:2"),
		finding("client_secret", "name", "line:3"),
	}
	out := correlateFindings(in, rules)

	primary := findClientSecret(out)
	if !hasTag(primary.Tags, "oauth-client-credentials") {
		t.Fatalf("client_id pairing should win: tags=%v", primary.Tags)
	}
	if len(primary.Correlated) != 1 || primary.Correlated[0].Name != "client_id" {
		t.Errorf("want client_id folded, got %+v", primary.Correlated)
	}
}

// findClientSecret returns the root finding named client_secret (any case), for
// assertions when other roots may remain alongside it.
func findClientSecret(findings []Finding) Finding {
	for _, f := range findings {
		if strings.EqualFold(f.Name, "client_secret") {
			return f
		}
	}
	return Finding{}
}

func TestBuiltinJWTURLCorrelation(t *testing.T) {
	rules := mustCorrelations(t, nil)

	// A JWT (reason jwt_indicator) folds in the preceding service URL.
	in := []Finding{
		finding("auth_url", "name", "line:1"),
		finding("token", "jwt_indicator", "line:2"),
	}
	out := correlateFindings(in, rules)
	if len(out) != 1 || !hasTag(out[0].Tags, "jwt-url") || len(out[0].Correlated) != 1 {
		t.Fatalf("jwt-url pairing not applied: %+v", out)
	}
	if out[0].Correlated[0].Name != "auth_url" {
		t.Errorf("want auth_url folded into jwt, got %+v", out[0].Correlated)
	}

	// The pattern-matched form (gitleaks:jwt) also pairs.
	in = []Finding{
		finding("BASE_URL", "info:azure-app-service", "line:1"),
		finding("token", "gitleaks:jwt", "line:2"),
	}
	out = correlateFindings(in, rules)
	if len(out) != 1 || !hasTag(out[0].Tags, "jwt-url") {
		t.Fatalf("gitleaks:jwt did not pair with URL: %+v", out)
	}

	// A key whose name reads like a JWT also pairs, even when its value was not
	// classified as a JWT by the detector (reason is a generic name match).
	in = []Finding{
		finding("auth_url", "name", "line:1"),
		finding("jwt_secret", "name", "line:2"),
	}
	out = correlateFindings(in, rules)
	if len(out) != 1 || !hasTag(out[0].Tags, "jwt-url") {
		t.Fatalf("name-based jwt did not pair with URL: %+v", out)
	}
}

func TestBuiltinClientIDURLCorrelation(t *testing.T) {
	rules := mustCorrelations(t, nil)

	in := []Finding{
		finding("token_url", "name", "line:1"),
		finding("client_id", "name", "line:2"),
	}
	out := correlateFindings(in, rules)
	if len(out) != 1 || !hasTag(out[0].Tags, "client-id-url") || len(out[0].Correlated) != 1 {
		t.Fatalf("client-id-url pairing not applied: %+v", out)
	}
	if out[0].Correlated[0].Name != "token_url" {
		t.Errorf("want token_url folded into client_id, got %+v", out[0].Correlated)
	}
}

func TestBuiltinAPIKeyURLCorrelation(t *testing.T) {
	rules := mustCorrelations(t, nil)

	in := []Finding{
		finding("token_url", "name", "line:1"),
		finding("x-api-key", "name", "line:2"),
	}
	out := correlateFindings(in, rules)
	if len(out) != 1 || !hasTag(out[0].Tags, "api-key-url") || len(out[0].Correlated) != 1 {
		t.Fatalf("api-key-url pairing not applied: %+v", out)
	}
	if out[0].Correlated[0].Name != "token_url" {
		t.Errorf("want token_url folded into x-api-key, got %+v", out[0].Correlated)
	}
}

func TestClientIDURLStillFoldsIntoClientSecret(t *testing.T) {
	// A URL preceding a client_id/client_secret pair is grabbed by client-id-url,
	// but the client_id remains available to oauth-client-credentials (tagged, not
	// removed) so the canonical secret pairing still wins the client_secret.
	rules := mustCorrelations(t, nil)

	in := []Finding{
		finding("token_url", "name", "line:1"),
		finding("client_id", "name", "line:2"),
		finding("client_secret", "name", "line:3"),
	}
	out := correlateFindings(in, rules)

	secret := findClientSecret(out)
	if !hasTag(secret.Tags, "oauth-client-credentials") {
		t.Fatalf("client_secret should still pair with client_id: tags=%v", secret.Tags)
	}
	if len(secret.Correlated) != 1 || secret.Correlated[0].Name != "client_id" {
		t.Errorf("want client_id folded into client_secret, got %+v", secret.Correlated)
	}
}

func TestBuiltinPasswordCorrelations(t *testing.T) {
	rules := mustCorrelations(t, nil)

	// Both a user and a URL present: the richer password-credentials rule wins and
	// folds both partners.
	in := []Finding{
		finding("username", "name", "line:1"),
		finding("service_url", "name", "line:2"),
		finding("password", "name", "line:3"),
	}
	out := correlateFindings(in, rules)
	if len(out) != 1 || !hasTag(out[0].Tags, "password-credentials") || len(out[0].Correlated) != 2 {
		t.Fatalf("password-credentials pairing not applied: %+v", out)
	}

	// Only a user present: falls back to password-user.
	in = []Finding{
		finding("db_user", "name", "line:1"),
		finding("password", "name", "line:2"),
	}
	out = correlateFindings(in, rules)
	if len(out) != 1 || !hasTag(out[0].Tags, "password-user") || len(out[0].Correlated) != 1 {
		t.Fatalf("password-user fallback not applied: %+v", out)
	}

	// Only a URL present: falls back to password-url.
	in = []Finding{
		finding("api_url", "name", "line:1"),
		finding("passwd", "name", "line:2"),
	}
	out = correlateFindings(in, rules)
	if len(out) != 1 || !hasTag(out[0].Tags, "password-url") || len(out[0].Correlated) != 1 {
		t.Fatalf("password-url fallback not applied: %+v", out)
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
