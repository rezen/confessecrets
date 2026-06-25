package scanner

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// makeJWT builds an unsigned JWT (header.payload.sig) whose payload encodes the
// given claims. The standard header begins with "eyJh", satisfying detection.
func makeJWT(t *testing.T, claims map[string]any) string {
	t.Helper()

	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}

	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	body := base64.RawURLEncoding.EncodeToString(payload)

	return header + "." + body + ".sig"
}

// testRules compiles a permissive rule set used across detection tests.
func testRules(t *testing.T) []Rule {
	t.Helper()

	rules, err := CompileRules([]RuleConfig{{
		NamePaths:   []string{"name", "key", "field"},
		ValuePaths:  []string{"value", "val", "secret"},
		NameRegexes: []NameRegexEntry{{Regex: `(?i)(secret|token|api[_-]?key|password|passwd|pwd|credential|key|auth)`}},
		MinValueLen: 8,
	}})
	if err != nil {
		t.Fatalf("compileRules: %v", err)
	}

	return rules
}

// keySet maps each finding's name to its raw value for convenient assertions.
func keySet(findings []Finding) map[string]string {
	out := make(map[string]string, len(findings))
	for _, f := range findings {
		out[f.Name] = f.RawValue
	}
	return out
}

func TestDetectorFor(t *testing.T) {
	tests := []struct {
		path string
		want Detector
	}{
		{"config.json", JSONDetector{}},
		{"settings.jsonc", JSONDetector{}},
		{"values.yaml", YAMLDetector{}},
		{"values.yml", YAMLDetector{}},
		{"web.xml", XMLDetector{}},
		{"web.config", XMLDetector{}},
		{"App.config", XMLDetector{}},
		{"MyApp.dll.config", XMLDetector{}},
		{".env", DotenvDetector{}},
		{".env.local", DotenvDetector{}},
		{"app.env", DotenvDetector{}},
		{"notes.txt", nil},
		{"binary", nil},
	}

	for _, tt := range tests {
		got := detectorFor(tt.path)
		if got != tt.want {
			t.Errorf("detectorFor(%q) = %T, want %T", tt.path, got, tt.want)
		}
	}
}

func TestIsLikelySecretValue(t *testing.T) {
	const minLen = 8
	rule := Rule{MinValueLen: minLen}

	tests := []struct {
		name  string
		value string
		want  bool
	}{
		// Positive: classified via classifySecretReason regardless of length/wordlist.
		{"jwt token", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.sig", true},
		{"private key", "-----BEGIN RSA PRIVATE KEY-----", true},
		{"url with credentials", "https://user:p4ssw0rd@example.com/path", true},
		{"url secret query param", "https://example.com/cb?access_token=abc123", true},
		{"connection string", "Server=db;User Id=admin;Password=hunter2;", true},

		// Positive: high-entropy-ish opaque value passes the generic checks.
		{"random api key", "sk_live_8Fh2kLmQ9zXc4Tg", true},
		{"long hex digest", "9f86d081884c7d659a2feaa0c55ad015", true},

		// Negative: too short.
		{"short value", "abc12", false},

		// Negative: empty / whitespace.
		{"empty", "", false},
		{"whitespace only", "   ", false},

		// Negative: template / interpolation placeholders.
		{"shell command substitution", "$(cat /run/secrets/token)", false},
		{"shell var", "${DATABASE_PASSWORD}", false},
		{"go template", "{{ .Values.password }}", false},
		{"at-delimited var", "@DB_PASSWORD@", false},
		{"percent-delimited var", "%DB_PASSWORD%", false},
		{"embedded shell var", "jdbc:mysql://host/db?password=${PW}", false},

		// Negative: natural language sentences are not secrets.
		{"sentence", "This is the default configuration value here", false},
		// Non-ASCII (Vietnamese) prose must be recognized as natural language.
		{"vietnamese sentence", "Vui lòng nhập mã bảo mật gồm sáu chữ số mà chúng tôi đã gửi đến email của bạn", false},
		// Hyphenated medical prose is natural language, not a secret.
		{"hyphenated medical prose", " Transplantation medicine, quantification of donor-derived cell-free DNA using up to 12 single-nucleotide polymorphisms (SNPs) previously identified, plasma, reported as percentage of donor-derived cell-free DNA with risk for active rejection", false},
		// Brand/product prose with a digit and a standalone separator is not a secret.
		{"brand prose with separator", "Pfizer-BioNTech Covid-19 vaccine administration - first dose", false},
		// Short clinical note with a slashed abbreviation is prose, not a secret.
		{"clinical note with slash", "Team remote e/m est. pt 10mins", false},
		// Natural language that includes a code/number token (e.g. medical text).
		// 8 of 10 words are alpha (ratio exactly 0.80), so it must read as language,
		// not a secret.
		{"medical description", " Injection, atropine sulfate, not therapeutically equivalent to j0461, 0.01 mg", false},

		// Negative: common placeholder / non-secret words.
		{"true", "true", false},
		{"false", "false", false},
		{"null", "null", false},
		{"none", "none", false},
		{"changeme", "changeme", false},
		{"password literal", "password", false},
		{"example", "example", false},
		{"test", "test", false},
		{"dummy", "dummy", false},
		{"undefined", "undefined", false},
		{"non-secret case insensitive", "ChangeMe", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isLikelySecretValue("opaque", tt.value, rule); got != tt.want {
				t.Errorf("isLikelySecretValue(%q, %d) = %v, want %v", tt.value, minLen, got, tt.want)
			}
		})
	}
}

// TestIsTemplatePlaceholder covers the variable/template placeholder detection
// used to skip substitution targets: the brace/paren forms match anywhere in the
// value, while the single-char @VAR@ / %VAR% forms match only a whole value so
// they don't suppress real secrets that merely contain '@' or '%'.
func TestIsTemplatePlaceholder(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  bool
	}{
		// Brace/paren forms — matched anywhere in the value.
		{"shell var", "${DB_HOST}", true},
		{"shell var quoted", `"${DB_HOST}"`, true},
		{"command substitution", "$(cat /run/secrets/pw)", true},
		{"mustache", "{{ db_host }}", true},
		{"go template", "{{ .Values.password }}", true},
		{"embedded shell var", "jdbc:mysql://h/db?password=${PW}", true},

		// Single-char forms — only a whole-value match counts.
		{"at var", "@DB_HOST@", true},
		{"percent var", "%DB_HOST%", true},
		{"at var with dots", "@project.version@", true},

		// Negative: not placeholders, and embedded @/% that must not over-match.
		{"plain secret", "sk_live_8Fh2kLmQ9zXc4Tg", false},
		{"email-ish", "user@example.com", false},
		{"url-encoded password", "p%41ss%2Fword", false},
		{"embedded at not whole value", "host=@DB_HOST@/db", false},
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isTemplatePlaceholder(tt.value); got != tt.want {
				t.Errorf("isTemplatePlaceholder(%q) = %v, want %v", tt.value, got, tt.want)
			}
		})
	}
}

// TestIsLikelySecretValueEntropyGate covers the rule-configured MinEntropy gate:
// once set, a low-variety value that clears the length and wordlist checks is
// still dropped, while a high-variety value of the same length passes.
func TestIsLikelySecretValueEntropyGate(t *testing.T) {
	const lowVariety = "abababababababab"   // 1 bit/symbol
	const highVariety = "Ab3Df9Gh2Jk5Lm8Qp" // ~4 bits/symbol

	// Without a gate both pass (long enough, not placeholders).
	open := Rule{MinValueLen: 8}
	if !isLikelySecretValue("token", lowVariety, open) {
		t.Errorf("ungated low-variety value should pass")
	}

	// With a gate the low-variety value is rejected, the high-variety one kept.
	gated := Rule{MinValueLen: 8, MinEntropy: 3.0}
	if isLikelySecretValue("token", lowVariety, gated) {
		t.Errorf("gated low-variety value should be rejected")
	}
	if !isLikelySecretValue("token", highVariety, gated) {
		t.Errorf("gated high-variety value should pass")
	}

	// A value carrying a definite secret reason bypasses the gate even though it
	// is low-variety, because classifySecretReason short-circuits first.
	if !isLikelySecretValue("token", "-----BEGIN RSA PRIVATE KEY-----", gated) {
		t.Errorf("definite-secret value should bypass the entropy gate")
	}
}

// TestStopwords covers the built-in and configurable stopwords: a value is
// dropped when it contains (case-insensitively, by substring, as in gitleaks)
// any built-in or configured extra stopword, and kept otherwise.
func TestStopwords(t *testing.T) {
	// A built-in gitleaks stopword is matched by substring even when embedded.
	open := Rule{MinValueLen: 8}
	if isLikelySecretValue("token", "Kq7changemeVp9", open) {
		t.Errorf("value containing a built-in stopword should be rejected")
	}
	// A value clear of any built-in stopword passes without extra config.
	if !isLikelySecretValue("token", "Kq7Vbz9XpQr", open) {
		t.Errorf("stopword-free value should pass")
	}

	// Extra stopwords extend the built-in set and are matched the same way:
	// case-insensitively, by substring.
	gated := Rule{MinValueLen: 8, Stopwords: compileStopwords([]string{"redacted", "tbd"})}
	if isLikelySecretValue("token", "Kq7redactedVp9", gated) {
		t.Errorf("value containing a configured stopword should be rejected")
	}
	if isLikelySecretValue("token", "Kq7REDACTEDVp9", gated) {
		t.Errorf("configured stopword should match case-insensitively")
	}
	// Built-ins still apply when extras are configured.
	if isLikelySecretValue("token", "Kq7changemeVp9", gated) {
		t.Errorf("built-in stopword should still be rejected")
	}
	// A value matching neither built-in nor extra stopwords passes.
	if !isLikelySecretValue("token", "Kq7Vbz9XpQr", gated) {
		t.Errorf("non-stopword value should pass")
	}
}

// TestCompileConfigStopwordsAreGlobal verifies the top-level stopwords setting is
// applied to every compiled rule (it is a global setting, not per-rule).
func TestCompileConfigStopwordsAreGlobal(t *testing.T) {
	set, err := CompileConfig(Config{
		Rules: []RuleConfig{
			{NameRegexes: []NameRegexEntry{{Regex: `secret`}}},
			{NameRegexes: []NameRegexEntry{{Regex: `token`}}},
		},
		Stopwords: []string{"Redacted", " tbd "},
	})
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}

	if len(set.Rules) != 2 {
		t.Fatalf("got %d rules, want 2", len(set.Rules))
	}
	for i, r := range set.Rules {
		// Entries are normalized (lowercased, trimmed) and applied to each rule.
		if len(r.Stopwords) != 2 || r.Stopwords[0] != "redacted" || r.Stopwords[1] != "tbd" {
			t.Errorf("rule %d stopwords = %v, want [redacted tbd]", i, r.Stopwords)
		}
	}
}

// TestNameValueSimilarity covers the similarity score reported with findings: the
// max of normalized Levenshtein and Jaro-Winkler over the lowercased, unquoted
// inputs.
func TestNameValueSimilarity(t *testing.T) {
	// Identical (case-insensitive, value unquoted) scores exactly 1.
	for _, tc := range []struct{ name, value string }{
		{"password", "password"},
		{"token", "TOKEN"},
		{"secret", `"secret"`},
	} {
		if got := nameValueSimilarity(tc.name, tc.value); got != 1 {
			t.Errorf("nameValueSimilarity(%q, %q) = %v, want 1", tc.name, tc.value, got)
		}
	}

	// Prefix-weighted near-echoes score high (Jaro-Winkler boost).
	for _, tc := range []struct{ name, value string }{
		{"secret", "secrets"},
		{"passwd", "passw0rd"},
		{"password", "password1"},
	} {
		if got := nameValueSimilarity(tc.name, tc.value); got < 0.85 {
			t.Errorf("nameValueSimilarity(%q, %q) = %v, want >= 0.85", tc.name, tc.value, got)
		}
	}

	// A genuine opaque secret scores low.
	if got := nameValueSimilarity("api_key", "Xk9$mQ2vLp7wRt4z"); got >= 0.85 {
		t.Errorf("nameValueSimilarity(opaque) = %v, want < 0.85", got)
	}

	// Score is bounded to [0,1].
	for _, tc := range []struct{ name, value string }{
		{"a", "zzzzzzzz"}, {"", "anything"}, {"key", ""},
	} {
		if got := nameValueSimilarity(tc.name, tc.value); got < 0 || got > 1 {
			t.Errorf("nameValueSimilarity(%q, %q) = %v, out of [0,1]", tc.name, tc.value, got)
		}
	}
}

// TestIsLikelySecretValueSimilarityGate covers the configurable
// max_name_value_similarity suppression of near-echo placeholders.
func TestIsLikelySecretValueSimilarityGate(t *testing.T) {
	gated := Rule{MinValueLen: 8, MaxNameValueSimilarity: 0.85}

	// Near-echo: "Kq7Vbz9Xp1" is highly similar to "Kq7Vbz9Xp" -> dropped. (An
	// opaque, stopword-free pair is used so only the similarity gate is at play.)
	if isLikelySecretValue("Kq7Vbz9Xp", "Kq7Vbz9Xp1", gated) {
		t.Errorf("near-echo value should be dropped by the similarity gate")
	}

	// A real secret is dissimilar from its key name -> kept.
	if !isLikelySecretValue("Kq7Vbz9Xp", "Xk9$mQ2vLp7wRt4z", gated) {
		t.Errorf("dissimilar value should pass the similarity gate")
	}

	// Without the gate the near-echo would survive.
	open := Rule{MinValueLen: 8}
	if !isLikelySecretValue("Kq7Vbz9Xp", "Kq7Vbz9Xp1", open) {
		t.Errorf("near-echo should pass when the similarity gate is disabled")
	}
}

// TestValueEchoesName covers suppression of placeholder values that merely
// restate their key name.
func TestValueEchoesName(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  bool
	}{
		// Echoes: exact, case-folded, separator/camelCase-normalized, filler-wrapped.
		{"password", "password", true},
		{"token", "TOKEN", true},
		{"api_key", "your-api-key", true},
		{"apiKey", "your_api_key", true},
		{"api-key", "API_KEY", true},
		{"secret", "<my-secret>", true},
		{"clientSecret", "your-client-secret", true},
		{"access_key", "example access key", true},

		// Not echoes: real-ish values that merely contain or extend the name.
		{"password", "hunter2", false},
		{"api_key", "AKIAIOSFODNN7EXAMPLE", false},
		{"api_key", "api-key-prod-12345", false},
		{"password", "password123", false},
		{"secret", "", false},
		{"", "anything", false},
	}

	for _, tt := range tests {
		t.Run(tt.name+"="+tt.value, func(t *testing.T) {
			if got := valueEchoesName(tt.name, tt.value); got != tt.want {
				t.Errorf("valueEchoesName(%q, %q) = %v, want %v", tt.name, tt.value, got, tt.want)
			}
		})
	}
}

// TestMatchHighEntropy covers the generic, name-independent high-entropy
// detector wired into value scanning.
func TestMatchHighEntropy(t *testing.T) {
	const random = "Xa9Kd2Lp7Qm4Zr8Wb3Nc6Vt1Hf5Jg0Ys" // ~5 bits/symbol

	tests := []struct {
		name      string
		value     string
		rules     []Rule
		wantMatch bool
	}{
		{"disabled when threshold unset", random, []Rule{{MinValueLen: 8}}, false},
		{"high entropy flagged", random, []Rule{{MinValueLen: 8, HighEntropyThreshold: 4.0}}, true},
		{"low entropy not flagged", "abababababababab", []Rule{{MinValueLen: 8, HighEntropyThreshold: 4.0}}, false},
		{"whitespace-bearing value skipped", random + " " + random, []Rule{{MinValueLen: 8, HighEntropyThreshold: 4.0}}, false},
		{"over-long value skipped", strings.Repeat(random, 10), []Rule{{MinValueLen: 8, HighEntropyThreshold: 4.0}}, false},
		{"too short skipped", "Xa9Kd", []Rule{{MinValueLen: 8, HighEntropyThreshold: 1.0}}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reason := matchHighEntropy(tt.value, tt.rules)
			if got := reason != ""; got != tt.wantMatch {
				t.Fatalf("matchHighEntropy(%q) = %q, want match=%v", tt.value, reason, tt.wantMatch)
			}
			if tt.wantMatch && !strings.HasPrefix(reason, "high_entropy:") {
				t.Errorf("reason = %q, want a high_entropy: prefix", reason)
			}
		})
	}
}

func TestClassifySecretReason(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{"jwt prefix", "eyJhbGciOiJIUzI1NiJ9.abc.def", "jwt_indicator"},
		{"jwt embedded", "Bearer eyJhbGciOiJIUzI1NiJ9", "jwt_indicator"},
		// Header starting with a non-alg claim (typ first -> "eyJ0"), behind a Bearer prefix.
		{"jwt bearer typ-first header", "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.abc.def", "jwt_indicator"},
		{"url secret query param", "https://example.com/x?api_key=secret", "url_secret_query_param"},
		{"url credentials", "postgres://user:pass@localhost:5432/db", "url_credentials"},
		{"private key", "-----BEGIN OPENSSH PRIVATE KEY-----", "private_key_indicator"},
		{"connection string", "Host=db;Uid=root;Pwd=secret;", "connection_string_secret_indicator"},
		{"plain value", "just-some-value", ""},
		{"plain url no creds", "https://example.com/path", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifySecretReason(tt.value); got != tt.want {
				t.Errorf("classifySecretReason(%q) = %q, want %q", tt.value, got, tt.want)
			}
		})
	}
}

func TestHasJWTIndicator(t *testing.T) {
	tests := []struct {
		value string
		want  bool
	}{
		{"eyJhbGciOiJIUzI1NiJ9.payload.signature", true},
		{"prefix eyJhbGciOiJIUzI1NiJ9", true},
		{`"eyJhbGciOiJIUzI1NiJ9"`, true},                      // quoted scalar is normalized
		{"Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9", true}, // typ-first header behind Bearer prefix
		{"eyJraWQiOiJaWDBMTVwifQ.payload.sig", true},          // kid-first header
		{"notajwt.value.here", false},
		{"", false},
	}

	for _, tt := range tests {
		if got := hasJWTIndicator(tt.value); got != tt.want {
			t.Errorf("hasJWTIndicator(%q) = %v, want %v", tt.value, got, tt.want)
		}
	}
}

func TestLooksLikePrivateKey(t *testing.T) {
	tests := []struct {
		value string
		want  bool
	}{
		{"-----BEGIN PRIVATE KEY-----", true},
		{"-----BEGIN RSA PRIVATE KEY-----", true},
		{"-----BEGIN EC PRIVATE KEY-----", true},
		{"-----BEGIN OPENSSH PRIVATE KEY-----", true},
		{"-----begin rsa private key-----", true}, // case insensitive
		{"-----BEGIN CERTIFICATE-----", false},
		{"not a key", false},
	}

	for _, tt := range tests {
		if got := looksLikePrivateKey(tt.value); got != tt.want {
			t.Errorf("looksLikePrivateKey(%q) = %v, want %v", tt.value, got, tt.want)
		}
	}
}

func TestLooksLikeConnectionString(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{"user and password equals", "Server=db;User=admin;Password=secret;", true},
		{"uid and pwd", "Host=db;Uid=root;Pwd=secret;", true},
		// Password has a colon variant (password:/pwd:) but the user side only
		// matches "="-style keys, so a fully colon-style string is not detected.
		{"colon style not detected", "user:admin password:secret", false},
		{"colon password with equals user", "user=admin password:secret", true},
		{"username variant", "username=admin;password=secret", true},
		{"password only", "Password=secret;", false},
		{"user only", "User=admin;", false},
		{"neither", "Server=db;Port=5432;", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := looksLikeConnectionString(tt.value); got != tt.want {
				t.Errorf("looksLikeConnectionString(%q) = %v, want %v", tt.value, got, tt.want)
			}
		})
	}
}

func TestLooksLikeNaturalLanguage(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{"sentence", "the quick brown fox jumps", true},
		{"sentence with punctuation", "This is a default value.", true},
		{"vietnamese diacritics", "Vui lòng nhập mã bảo mật gồm sáu chữ số mà chúng tôi đã gửi đến email của bạn", true},
		// Hyphenated compound words (medical prose) count as natural language.
		{"hyphenated compounds", " Transplantation medicine, quantification of donor-derived cell-free DNA using up to 12 single-nucleotide polymorphisms (SNPs) previously identified, plasma, reported as percentage of donor-derived cell-free DNA with risk for active rejection", true},
		// Product/brand prose with a digit token and a standalone "-" separator.
		{"brand with separator dash", "Pfizer-BioNTech Covid-19 vaccine administration - first dose", true},
		// Slashed abbreviation ("e/m") should read as a word, not break the ratio.
		{"slashed abbreviation", "Team remote e/m est. pt 10mins", true},
		{"too few words", "one two three", false},
		{"opaque token", "sk_live_8Fh2kLmQ9zXc4Tg", false},
		{"mostly non-alpha words", "a1 b2 c3 d4 e5", false},
		// Exactly 0.80 alpha ratio (8/10) must count as natural language.
		{"ratio exactly 0.80", "Injection, atropine sulfate, not therapeutically equivalent to j0461, 0.01 mg", true},
		// Just below the 0.80 threshold (7/10) is not natural language.
		{"ratio just below 0.80", "atropine sulfate not therapeutically equivalent to j0461 0.01 0.02 mg", false},
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := looksLikeNaturalLanguage(tt.value); got != tt.want {
				t.Errorf("looksLikeNaturalLanguage(%q) = %v, want %v", tt.value, got, tt.want)
			}
		})
	}
}

func TestNameSignalsSecret(t *testing.T) {
	rules, err := CompileRules([]RuleConfig{{
		NameRegexes:        []NameRegexEntry{{Regex: `(?i)(secret|token|api[_-]?key|password|key|auth)`}},
		IgnoreNamePatterns: []string{`(?i)label`},
	}})
	if err != nil {
		t.Fatalf("compileRules: %v", err)
	}
	rule := rules[0]

	tests := []struct {
		name string
		want bool
	}{
		{"apiKey", true},
		{"password", true},
		{"client_secret", true},
		{"labelKey", false},    // matches name_regex via "key" but ignored by "label"
		{"Label", false},       // case-insensitive ignore
		{"displayName", false}, // does not match name_regex at all
	}

	for _, tt := range tests {
		if got := nameSignalsSecret(tt.name, rule); got != tt.want {
			t.Errorf("nameSignalsSecret(%q) = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestMatchValuePattern(t *testing.T) {
	tests := []struct {
		value string
		want  string
	}{
		{"AKIAIOSFODNN7EXAMPLE", "aws-access-token"},
		{"ghp_0123456789abcdefghijklmnopqrstuvwxyz", "github-pat"},
		{"gho_0123456789abcdefghijklmnopqrstuvwxyz", "github-oauth"},
		{"glpat-ABCDEFGHIJ1234567890", "gitlab-pat"},
		{"sk_live_abcdefghij1234567890", "stripe-access-token"},
		{"npm_abcdefghijklmnopqrstuvwxyz0123456789", "npm-access-token"},
		{"AIzaabcdefghijklmnopqrstuvwxyz012345678", "gcp-api-key"},
		{"shpss_0123456789abcdef0123456789abcdef", "shopify-shared-secret"},
		// Negatives: ordinary values must not match any token pattern.
		{"hunter2secret", ""},
		{"just a friendly note here", ""},
		{"https://example.com/path", ""},
		{"", ""},
	}

	for _, tt := range tests {
		if got := matchValuePattern(tt.value); got != tt.want {
			t.Errorf("matchValuePattern(%q) = %q, want %q", tt.value, got, tt.want)
		}
	}
}

func TestDetectValuePatternsRegardlessOfName(t *testing.T) {
	rules := testRules(t)

	// "comment" does not match the name regex, but the value is an AWS key, so
	// value scanning must flag it independently of the key name.
	content := strings.Join([]string{
		"comment=AKIAIOSFODNN7EXAMPLE",
		"note=nothing to see here at all",
	}, "\n")

	findings := detectEnvLines("app.env", []byte(content), RuleSet{Rules: rules})

	var got *Finding
	for i := range findings {
		if findings[i].Name == "comment" {
			got = &findings[i]
		}
		if findings[i].Name == "note" {
			t.Errorf("benign value should not be flagged: %+v", findings[i])
		}
	}

	if got == nil {
		t.Fatalf("expected AWS token flagged under benign key, got %+v", findings)
	}
	if got.Reason != "gitleaks:aws-access-token" {
		t.Errorf("reason = %q, want gitleaks:aws-access-token", got.Reason)
	}
}

func TestDetectInfoURLPatterns(t *testing.T) {
	cases := []struct {
		name    string
		value   string
		wantID  string
		wantHit bool
	}{
		{"azure app service", "https://myapp.azurewebsites.net/api", "azure-app-service", true},
		{"azure bare host", "myapp-prod.azurewebsites.net", "azure-app-service", true},
		{"aws lambda url", "https://abc123def.lambda-url.us-east-1.on.aws/", "aws-lambda-url", true},
		{"plain url not flagged", "https://example.com/path", "", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings := detectValuePatterns(ExaminationFocus{File: "f", Path: "line:7", Name: "endpoint", Value: tc.value}, RuleSet{})

			if !tc.wantHit {
				if len(findings) != 0 {
					t.Fatalf("expected no finding for %q, got %+v", tc.value, findings)
				}
				return
			}

			if len(findings) != 1 {
				t.Fatalf("expected one finding for %q, got %+v", tc.value, findings)
			}
			f := findings[0]
			if f.Level != levelInfo {
				t.Errorf("level = %q, want %q", f.Level, levelInfo)
			}
			if f.Reason != "info:"+tc.wantID {
				t.Errorf("reason = %q, want info:%s", f.Reason, tc.wantID)
			}
			if f.Line != 7 {
				t.Errorf("line = %d, want 7", f.Line)
			}
		})
	}
}

func TestInfoURLYieldsToSecretValue(t *testing.T) {
	// A secret query parameter on a recognized service URL must keep the value a
	// high-severity finding rather than downgrading it to info — but that secret
	// classification is name/structure-driven, so here we only assert the bare
	// endpoint URL is the info case while a gitleaks token in the same value wins.
	findings := detectValuePatterns(ExaminationFocus{File: "f", Path: "line:1", Name: "x", Value: "AKIAIOSFODNN7EXAMPLE.lambda-url.us-east-1.on.aws"}, RuleSet{})
	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %+v", findings)
	}
	if findings[0].Level != levelHigh || findings[0].Reason != "gitleaks:aws-access-token" {
		t.Errorf("secret token must win over info URL, got level=%q reason=%q", findings[0].Level, findings[0].Reason)
	}
}

func TestLineFromPath(t *testing.T) {
	cases := map[string]int{
		"line:2":               2,
		"[credentials] line:5": 5,
		"$.db.password":        0,
		"":                     0,
	}
	for path, want := range cases {
		if got := lineFromPath(path); got != want {
			t.Errorf("lineFromPath(%q) = %d, want %d", path, got, want)
		}
	}
}

func TestNewFindingDefaultsToHighLevel(t *testing.T) {
	f := newFinding("f", "line:3", "n", "v", "name", "value", "reason")
	if f.Level != levelHigh {
		t.Errorf("level = %q, want %q", f.Level, levelHigh)
	}
	if f.Line != 3 {
		t.Errorf("line = %d, want 3", f.Line)
	}
}

func TestDetectValuePatternsSuppressed(t *testing.T) {
	rules, err := CompileRules([]RuleConfig{{
		NameRegexes:         []NameRegexEntry{{Regex: `(?i)secret`}},
		IgnoreValuePrefixes: []string{"AKIA"},
	}})
	if err != nil {
		t.Fatalf("CompileRules: %v", err)
	}

	findings := detectValuePatterns(ExaminationFocus{File: "f", Path: "$.x", Name: "x", Value: "AKIAIOSFODNN7EXAMPLE"}, RuleSet{Rules: rules})
	if len(findings) != 0 {
		t.Errorf("ignore prefix should suppress value-pattern finding, got %+v", findings)
	}
}

func TestDetectEnvLinesIgnoresName(t *testing.T) {
	rules, err := CompileRules([]RuleConfig{{
		NameRegexes:        []NameRegexEntry{{Regex: `(?i)(secret|token|api[_-]?key|password|key|auth)`}},
		IgnoreNamePatterns: []string{`(?i)label`},
		MinValueLen:        8,
	}})
	if err != nil {
		t.Fatalf("compileRules: %v", err)
	}

	// An opaque value (not a recognizable token) isolates name-ignore behavior
	// from value-pattern scanning.
	content := strings.Join([]string{
		"API_KEY=Zk9QmWvTxLpAa12345",   // flagged via name
		"LABEL_KEY=just-a-plain-label", // matches via "key" but ignored by "label"
	}, "\n")

	findings := detectEnvLines("app.env", []byte(content), RuleSet{Rules: rules})

	names := keySet(findings)
	if _, ok := names["API_KEY"]; !ok {
		t.Errorf("expected API_KEY to be flagged, got %+v", findings)
	}
	if _, ok := names["LABEL_KEY"]; ok {
		t.Errorf("LABEL_KEY should be ignored by name, got %+v", findings)
	}
}

func TestDetectEnvLines(t *testing.T) {
	rules := testRules(t)

	content := strings.Join([]string{
		"# a comment",
		"export API_KEY=sk_live_8Fh2kLmQ9zXc4Tg",
		`DB_PASSWORD="hunter2secret"`,
		"PUBLIC_URL=https://example.com/path",   // url without creds, ignored
		"SECRET_NOTE=hi",                        // matches name regex but value too short
		"PLAIN=just a value",                    // key does not match name regex
		"AUTH_TOKEN=abcd12345 # inline comment", // inline comment stripped
	}, "\n")

	findings := detectEnvLines("app.env", []byte(content), RuleSet{Rules: rules})
	got := keySet(findings)

	want := map[string]string{
		"API_KEY":     "sk_live_8Fh2kLmQ9zXc4Tg",
		"DB_PASSWORD": "hunter2secret",
		"AUTH_TOKEN":  "abcd12345",
	}

	if len(got) != len(want) {
		t.Fatalf("got %d findings %v, want %d %v", len(got), got, len(want), want)
	}

	for name, value := range want {
		if got[name] != value {
			t.Errorf("finding %q = %q, want %q", name, got[name], value)
		}
	}
}

// TestDotenvDetectorStructured exercises the godotenv happy path through Detect,
// including an "export" prefix, a quoted value, and an inline comment.
func TestDotenvDetectorStructured(t *testing.T) {
	rules := testRules(t)

	content := strings.Join([]string{
		"# a comment",
		"export API_KEY=sk_live_8Fh2kLmQ9zXc4Tg",
		`DB_PASSWORD="hunter2secret"`,
		"PUBLIC_URL=https://example.com/path",   // url without creds, ignored
		"PLAIN=just a value",                    // key does not match name regex
		"AUTH_TOKEN=abcd12345 # inline comment", // inline comment stripped by godotenv
	}, "\n")

	findings := DotenvDetector{}.Detect("app.env", []byte(content), RuleSet{Rules: rules})
	got := keySet(findings)

	want := map[string]string{
		"API_KEY":     "sk_live_8Fh2kLmQ9zXc4Tg",
		"DB_PASSWORD": "hunter2secret",
		"AUTH_TOKEN":  "abcd12345",
	}
	for name, value := range want {
		if got[name] != value {
			t.Errorf("finding %q = %q, want %q", name, got[name], value)
		}
	}
	if _, ok := got["PLAIN"]; ok {
		t.Errorf("non-secret key 'PLAIN' should not be reported")
	}
}

// TestDotenvDetectorFallback feeds input godotenv rejects to confirm Detect
// still recovers secrets via the line scanner.
func TestDotenvDetectorFallback(t *testing.T) {
	rules := testRules(t)

	// A bare word line with no '=' is not valid dotenv and makes godotenv error,
	// forcing the line-scan fallback.
	content := strings.Join([]string{
		"this is not valid dotenv",
		"API_KEY=sk_live_8Fh2kLmQ9zXc4Tg",
	}, "\n")

	if _, err := parseDotenv([]byte(content)); err == nil {
		t.Skip("godotenv accepted the input; fallback not exercised")
	}

	findings := DotenvDetector{}.Detect("app.env", []byte(content), RuleSet{Rules: rules})
	if keySet(findings)["API_KEY"] != "sk_live_8Fh2kLmQ9zXc4Tg" {
		t.Fatalf("fallback line scan missed secret: %+v", findings)
	}
}

func TestDetectPropertiesLines(t *testing.T) {
	rules := testRules(t)

	content := strings.Join([]string{
		"# a comment",
		"! also a comment",
		"api.key=sk_live_8Fh2kLmQ9zXc4Tg",
		"db.password : hunter2secret",                  // colon separator with spaces
		"  auth.token   abcd12345secret",               // whitespace separator, leading indent
		"public.url=https://example.com/p",             // url without creds, ignored
		"secret.note=hi",                               // name matches but value too short
		"display.name=My Application",                  // key does not match name regex
		`jdbc.secret=user\=admin&pwd\=longsecretvalue`, // escaped '=' inside value
	}, "\n")

	findings := detectPropertiesLines("app.properties", []byte(content), RuleSet{Rules: rules})
	got := keySet(findings)

	want := map[string]string{
		"api.key":     "sk_live_8Fh2kLmQ9zXc4Tg",
		"db.password": "hunter2secret",
		"auth.token":  "abcd12345secret",
		"jdbc.secret": "user=admin&pwd=longsecretvalue",
	}

	if len(got) != len(want) {
		t.Fatalf("got %d findings %v, want %d %v", len(got), got, len(want), want)
	}

	for name, value := range want {
		if got[name] != value {
			t.Errorf("finding %q = %q, want %q", name, got[name], value)
		}
	}
}

// TestPropertiesDetectorStructured exercises the magiconair happy path through
// Detect, including a multi-line continuation and a literal (unexpanded) value.
func TestPropertiesDetectorStructured(t *testing.T) {
	rules := testRules(t)

	content := strings.Join([]string{
		"# config",
		"db.host=localhost",
		"db.password=hunter2secret",
		`api.token=sk_live_8Fh2k\`,
		"  LmQ9zXc4Tg",
		"vault.secret=${VAULT_PW}", // expansion disabled -> stays literal, skipped by prefix
	}, "\n")

	findings := PropertiesDetector{}.Detect("app.properties", []byte(content), RuleSet{Rules: rules})
	got := keySet(findings)

	if got["db.password"] != "hunter2secret" {
		t.Errorf("db.password = %q, want hunter2secret", got["db.password"])
	}
	if got["api.token"] != "sk_live_8Fh2kLmQ9zXc4Tg" {
		t.Errorf("api.token = %q, want continuation joined", got["api.token"])
	}
	if _, ok := got["db.host"]; ok {
		t.Errorf("non-secret key 'db.host' should not be reported")
	}
	if v, ok := got["vault.secret"]; ok {
		t.Errorf("literal ${...} value should be skipped, got %q", v)
	}
}

// TestPropertiesDetectorFallback feeds input magiconair rejects (a malformed
// unicode escape) to confirm Detect still recovers secrets via the line scanner.
func TestPropertiesDetectorFallback(t *testing.T) {
	rules := testRules(t)

	content := strings.Join([]string{
		"api.secret=abcd1234efgh5678",
		`broken=\uZZZZ`, // invalid unicode escape -> parse error
	}, "\n")

	if _, err := parseProperties([]byte(content)); err == nil {
		t.Skip("parser accepted the input; fallback not exercised")
	}

	findings := PropertiesDetector{}.Detect("app.properties", []byte(content), RuleSet{Rules: rules})
	if keySet(findings)["api.secret"] != "abcd1234efgh5678" {
		t.Fatalf("fallback line scan missed secret: %+v", findings)
	}
}

func TestDetectPropertiesLineContinuation(t *testing.T) {
	rules := testRules(t)

	// The value spans three physical lines; the finding reports the first.
	content := strings.Join([]string{
		"# header",
		`api.secret=abcd1234\`,
		`  efgh5678\`,
		"  ijkl9012",
	}, "\n")

	findings := detectPropertiesLines("app.properties", []byte(content), RuleSet{Rules: rules})

	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(findings), findings)
	}
	if findings[0].RawValue != "abcd1234efgh5678ijkl9012" {
		t.Errorf("value = %q, want joined continuation", findings[0].RawValue)
	}
	if findings[0].Line != 2 {
		t.Errorf("line = %d, want 2 (start of logical line)", findings[0].Line)
	}
	if findings[0].Path != "" {
		t.Errorf("path = %q, want empty (bare line:N is redundant with Line)", findings[0].Path)
	}
}

func TestPropertiesDetectorRouting(t *testing.T) {
	if _, ok := detectorFor("config/app.properties").(PropertiesDetector); !ok {
		t.Errorf("detectorFor(.properties) = %T, want PropertiesDetector", detectorFor("config/app.properties"))
	}
}

func TestDetectINILines(t *testing.T) {
	rules := testRules(t)

	content := strings.Join([]string{
		"; a comment",
		"# also a comment",
		"region=us-east-1plain", // name does not match regex
		"",
		"[database]",
		"password = hunter2secret",
		`api_token = "sk_live_8Fh2kLmQ9zXc4Tg"`, // quoted value unwrapped
		"host = localhost",                      // not a secret name
		"",
		"[auth]",
		"client_secret: MnvK3jqQc8gMst3Bc", // colon separator
		"note = hi",                        // name matches but value too short
	}, "\n")

	findings := detectINILines("app.ini", []byte(content), RuleSet{Rules: rules})
	got := keySet(findings)

	want := map[string]string{
		"password":      "hunter2secret",
		"api_token":     "sk_live_8Fh2kLmQ9zXc4Tg",
		"client_secret": "MnvK3jqQc8gMst3Bc",
	}

	if len(got) != len(want) {
		t.Fatalf("got %d findings %v, want %d %v", len(got), got, len(want), want)
	}

	for name, value := range want {
		if got[name] != value {
			t.Errorf("finding %q = %q, want %q", name, got[name], value)
		}
	}
}

func TestDetectINISectionInPath(t *testing.T) {
	rules := testRules(t)

	content := strings.Join([]string{
		"[credentials]",
		"secret = abcd1234efgh5678",
	}, "\n")

	findings := detectINILines("app.ini", []byte(content), RuleSet{Rules: rules})

	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(findings), findings)
	}
	if findings[0].Path != "[credentials] line:2" {
		t.Errorf("path = %q, want section-qualified location", findings[0].Path)
	}
}

func TestINIDetectorRouting(t *testing.T) {
	if _, ok := detectorFor("config/app.ini").(INIDetector); !ok {
		t.Errorf("detectorFor(.ini) = %T, want INIDetector", detectorFor("config/app.ini"))
	}
}

// TestINIDetectorStructured exercises the go-ini happy path through Detect.
func TestINIDetectorStructured(t *testing.T) {
	rules := testRules(t)

	content := strings.Join([]string{
		"; app config",
		"[database]",
		"host = localhost",
		"password = hunter2secret",
		"[auth]",
		`api_token = "sk_live_8Fh2kLmQ9zXc4Tg"`,
	}, "\n")

	findings := INIDetector{}.Detect("app.ini", []byte(content), RuleSet{Rules: rules})
	got := keySet(findings)

	if got["password"] != "hunter2secret" || got["api_token"] != "sk_live_8Fh2kLmQ9zXc4Tg" {
		t.Fatalf("structured parse missed secrets: %v", got)
	}
	if _, ok := got["host"]; ok {
		t.Errorf("non-secret key 'host' should not be reported")
	}
}

// TestINIDetectorFallback feeds input go-ini rejects (a key/value before any
// section, with a duplicated bare key) to confirm Detect still recovers secrets
// via the line scanner.
func TestINIDetectorFallback(t *testing.T) {
	rules := testRules(t)

	// A boolean-style bare key makes strict go-ini parsing fail, forcing the
	// line-scan fallback.
	content := strings.Join([]string{
		"debug",
		"[creds]",
		"secret = abcd1234efgh5678",
	}, "\n")

	if _, err := parseINI([]byte(content)); err == nil {
		t.Skip("go-ini accepted the input; fallback not exercised")
	}

	findings := INIDetector{}.Detect("app.ini", []byte(content), RuleSet{Rules: rules})
	if keySet(findings)["secret"] != "abcd1234efgh5678" {
		t.Fatalf("fallback line scan missed secret: %+v", findings)
	}
}

func TestDetectXML(t *testing.T) {
	rules := testRules(t)

	content := `<config>
  <password>hunter2secret</password>
  <db host="localhost" password="sup3rs3cretvalue"/>
  <add key="ClientSecret" value="abcd1234efgh5678"/>
  <add key="DisplayName" value="My Application"/>
  <endpoint>https://example.com/path</endpoint>
  <note>just a friendly note here</note>
</config>`

	findings := detectXML("app.xml", []byte(content), RuleSet{Rules: rules})
	got := keySet(findings)

	if got["password"] != "hunter2secret" && got["password"] != "sup3rs3cretvalue" {
		t.Errorf("expected a password finding, got %v", got)
	}
	if _, ok := got["ClientSecret"]; !ok {
		t.Errorf("expected name/value pair finding for ClientSecret, got %v", got)
	}

	for _, f := range findings {
		if f.RawValue == "My Application" {
			t.Errorf("display name should not be flagged: %+v", f)
		}
		if f.RawValue == "just a friendly note here" {
			t.Errorf("friendly note should not be flagged: %+v", f)
		}
		if f.RawValue == "https://example.com/path" {
			t.Errorf("plain url should not be flagged: %+v", f)
		}
	}
}

func TestDetectDotNetConfig(t *testing.T) {
	rules := testRules(t)

	// Representative web.config: appSettings name/value pairs are the canonical
	// secret location in .NET configuration files.
	content := `<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <appSettings>
    <add key="ApiKeySecret" value="abcd1234efgh5678" />
    <add key="DisplayName" value="My Application" />
  </appSettings>
</configuration>`

	findings := detectXML("web.config", []byte(content), RuleSet{Rules: rules})
	got := keySet(findings)

	if _, ok := got["ApiKeySecret"]; !ok {
		t.Errorf("expected name/value pair finding for ApiKeySecret, got %v", got)
	}

	for _, f := range findings {
		if f.RawValue == "My Application" {
			t.Errorf("display name should not be flagged: %+v", f)
		}
	}
}

func TestDetectXMLAttrReasons(t *testing.T) {
	rules := testRules(t)

	// A connectionStrings entry whose name attribute ("DefaultConnection") is
	// benign but whose connectionString carries a credential should still be
	// flagged via classifySecretReason.
	content := `<configuration>
  <connectionStrings>
    <add name="DefaultConnection"
         connectionString="Server=db;User Id=sa;Password=hunter2secret;" />
    <add name="Telemetry" connectionString="Server=metrics;Trusted_Connection=True;" />
  </connectionStrings>
</configuration>`

	findings := detectXML("web.config", []byte(content), RuleSet{Rules: rules})

	var flagged bool
	for _, f := range findings {
		if f.Reason == reasonConnectionStringIndicator &&
			f.Value != "" && f.NamePath == "xml_attr" {
			flagged = true
		}
		if strings.Contains(f.RawValue, "Trusted_Connection") {
			t.Errorf("credential-free connection string should not be flagged: %+v", f)
		}
	}

	if !flagged {
		t.Errorf("expected connection-string finding from attribute value, got %+v", findings)
	}
}

func TestDetectXMLTextReason(t *testing.T) {
	rules := testRules(t)

	// A benignly named element whose text is a credential-bearing connection
	// string should still be flagged via classifySecretReason.
	content := `<settings>
  <database>Server=db;User Id=sa;Password=hunter2secret;</database>
  <region>Server=metrics;Trusted_Connection=True;</region>
</settings>`

	findings := detectXML("app.config", []byte(content), RuleSet{Rules: rules})

	var flagged bool
	for _, f := range findings {
		if f.Reason == reasonConnectionStringIndicator &&
			f.Name == "database" && f.NamePath == "xml_element" {
			flagged = true
		}
		if strings.Contains(f.RawValue, "Trusted_Connection") {
			t.Errorf("credential-free connection string should not be flagged: %+v", f)
		}
	}

	if !flagged {
		t.Errorf("expected connection-string finding from element text, got %+v", findings)
	}
}

func TestParseJWT(t *testing.T) {
	// Header + payload {"iss":"auth.example.com","iat":1700000000,"exp":1700003600}
	// base64url-encoded, signature omitted (irrelevant to claim parsing).
	const header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
	const payload = "eyJpc3MiOiJhdXRoLmV4YW1wbGUuY29tIiwiaWF0IjoxNzAwMDAwMDAwLCJleHAiOjE3MDAwMDM2MDB9"
	jwt := header + "." + payload + ".sig"

	t.Run("extracts claims", func(t *testing.T) {
		j := parseJWT(jwt)
		if j == nil {
			t.Fatal("expected jwt, got nil")
		}
		if j.Issuer != "auth.example.com" {
			t.Errorf("Issuer = %q, want auth.example.com", j.Issuer)
		}
		if j.Iat != 1700000000 {
			t.Errorf("Iat = %d, want 1700000000", j.Iat)
		}
		if j.Expiration != 1700003600 {
			t.Errorf("Expiration = %d, want 1700003600", j.Expiration)
		}
		// exp is in 2023, so the token is expired relative to now.
		if !j.IsExpired {
			t.Errorf("IsExpired = false, want true for a 2023 exp")
		}
	})

	t.Run("decodes header", func(t *testing.T) {
		j := parseJWT(jwt)
		if j == nil {
			t.Fatal("expected jwt, got nil")
		}
		if j.Header["alg"] != "HS256" {
			t.Errorf("Header[alg] = %v, want HS256", j.Header["alg"])
		}
		if j.Header["typ"] != "JWT" {
			t.Errorf("Header[typ] = %v, want JWT", j.Header["typ"])
		}
	})

	t.Run("expired token", func(t *testing.T) {
		tok := makeJWT(t, map[string]any{"iss": "x", "exp": time.Now().Add(-time.Hour).Unix()})
		j := parseJWT(tok)
		if j == nil || !j.IsExpired {
			t.Errorf("expected IsExpired true, got %+v", j)
		}
	})

	t.Run("valid (unexpired) token", func(t *testing.T) {
		tok := makeJWT(t, map[string]any{"iss": "x", "exp": time.Now().Add(time.Hour).Unix()})
		j := parseJWT(tok)
		if j == nil || j.IsExpired {
			t.Errorf("expected IsExpired false, got %+v", j)
		}
	})

	t.Run("no exp claim is not expired", func(t *testing.T) {
		tok := makeJWT(t, map[string]any{"iss": "x", "iat": 1700000000})
		j := parseJWT(tok)
		if j == nil || j.IsExpired {
			t.Errorf("expected IsExpired false without exp, got %+v", j)
		}
	})

	t.Run("extra holds remaining claims", func(t *testing.T) {
		tok := makeJWT(t, map[string]any{
			"iss":  "auth.example.com",
			"exp":  1700003600,
			"sub":  "user-123",
			"aud":  "my-api",
			"role": "admin",
		})

		j := parseJWT(tok)
		if j == nil {
			t.Fatal("expected jwt, got nil")
		}

		// Reserved claims stay out of Extra.
		if _, ok := j.Extra["iss"]; ok {
			t.Error("iss should not appear in Extra")
		}
		if _, ok := j.Extra["exp"]; ok {
			t.Error("exp should not appear in Extra")
		}

		// Remaining claims land in Extra.
		if j.Extra["sub"] != "user-123" {
			t.Errorf("Extra[sub] = %v, want user-123", j.Extra["sub"])
		}
		if j.Extra["aud"] != "my-api" {
			t.Errorf("Extra[aud] = %v, want my-api", j.Extra["aud"])
		}
		if j.Extra["role"] != "admin" {
			t.Errorf("Extra[role] = %v, want admin", j.Extra["role"])
		}
		if len(j.Extra) != 3 {
			t.Errorf("Extra = %v, want exactly 3 entries", j.Extra)
		}
	})

	t.Run("token with Bearer prefix", func(t *testing.T) {
		if j := parseJWT("Bearer " + jwt); j == nil || j.Issuer != "auth.example.com" {
			t.Errorf("expected issuer from prefixed token, got %+v", j)
		}
	})

	t.Run("non-jwt value", func(t *testing.T) {
		if j := parseJWT("sk_live_8Fh2kLmQ9zXc4Tg"); j != nil {
			t.Errorf("expected nil jwt for non-jwt, got %+v", j)
		}
	})

	t.Run("finding carries meta", func(t *testing.T) {
		f := newFinding("f", "$", "k", "v", "token", jwt, "jwt_indicator")
		if f.Meta == nil || f.Meta.JWT == nil || f.Meta.JWT.Issuer != "auth.example.com" {
			t.Errorf("finding meta = %+v, want jwt issuer auth.example.com", f.Meta)
		}

		plain := newFinding("f", "$", "k", "v", "pwd", "hunter2secret", "x")
		if plain.Meta != nil {
			t.Errorf("non-jwt finding should have nil meta, got %+v", plain.Meta)
		}
	})
}

func TestParseURLMeta(t *testing.T) {
	t.Run("url with credentials", func(t *testing.T) {
		var meta Meta
		if !parseURLMeta("postgres://admin:s3cret@db.example.com:5432/app", &meta) {
			t.Fatal("expected true for URL with credentials")
		}
		if meta.Username != "admin" {
			t.Errorf("Username = %q, want admin", meta.Username)
		}
		if meta.Host != "db.example.com:5432" {
			t.Errorf("Host = %q, want db.example.com:5432", meta.Host)
		}
		if meta.URL == "" {
			t.Error("URL should be set")
		}
	})

	t.Run("url without credentials", func(t *testing.T) {
		var meta Meta
		if parseURLMeta("https://example.com/path", &meta) {
			t.Errorf("expected false for URL without credentials, got %+v", meta)
		}
	})

	t.Run("non-url value", func(t *testing.T) {
		var meta Meta
		if parseURLMeta("not a url", &meta) {
			t.Errorf("expected false for non-URL, got %+v", meta)
		}
	})
}

func TestParseConnStringMeta(t *testing.T) {
	t.Run("populates fields", func(t *testing.T) {
		var meta Meta
		conn := "Server=tcp:db.example.net,1433;User Id=svc;Password=p@ss;Client Id=abc-123;Client Secret=topsecret"
		if !parseConnStringMeta(conn, &meta) {
			t.Fatal("expected true for connection string")
		}
		if meta.Username != "svc" {
			t.Errorf("Username = %q, want svc", meta.Username)
		}
		if meta.Host != "tcp:db.example.net,1433" {
			t.Errorf("Host = %q, want tcp:db.example.net,1433", meta.Host)
		}
		if meta.ClientID != "abc-123" {
			t.Errorf("ClientID = %q, want abc-123", meta.ClientID)
		}
		if meta.ClientKey != "topsecret" {
			t.Errorf("ClientKey = %q, want topsecret", meta.ClientKey)
		}
	})

	t.Run("non-connection-string value", func(t *testing.T) {
		var meta Meta
		if parseConnStringMeta("just a plain value", &meta) {
			t.Errorf("expected false for non-connection-string, got %+v", meta)
		}
	})
}

func TestHasSecretQueryParam(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{"access_token", "https://example.com/cb?access_token=abc", true},
		{"api key", "https://example.com?apikey=xyz", true},
		{"signature", "https://example.com?sig=deadbeef", true},
		{"empty value param", "https://example.com?token=", false},
		{"no secret param", "https://example.com?page=2", false},
		{"not a url", "just a string", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hasSecretQueryParam(tt.value); got != tt.want {
				t.Errorf("hasSecretQueryParam(%q) = %v, want %v", tt.value, got, tt.want)
			}
		})
	}
}

func TestIsURLWithoutCredentials(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{"plain url", "https://example.com/path", true},
		{"url with userinfo", "https://user:pass@example.com", false},
		{"url with secret query param", "https://example.com?token=abc", false},
		{"not a url", "plain-value", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isURLWithoutCredentials(tt.value); got != tt.want {
				t.Errorf("isURLWithoutCredentials(%q) = %v, want %v", tt.value, got, tt.want)
			}
		})
	}
}
