package scanner

import (
	"math"
	"strings"
	"testing"
)

func TestCompileDetectorsErrors(t *testing.T) {
	tests := []struct {
		name string
		cfg  DetectorConfig
	}{
		{
			name: "missing name",
			cfg:  DetectorConfig{Regex: map[string]string{"v": `x`}},
		},
		{
			name: "missing regex",
			cfg:  DetectorConfig{Name: "d"},
		},
		{
			name: "invalid regex",
			cfg:  DetectorConfig{Name: "d", Regex: map[string]string{"v": `([`}},
		},
		{
			name: "invalid exclude regex",
			cfg:  DetectorConfig{Name: "d", Regex: map[string]string{"v": `x`}, ExcludeRegexesMatch: []string{`([`}},
		},
		{
			name: "unknown primary regex name",
			cfg:  DetectorConfig{Name: "d", Regex: map[string]string{"v": `x`}, PrimaryRegexName: "nope"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := CompileDetectors([]DetectorConfig{tt.cfg}); err == nil {
				t.Errorf("CompileDetectors(%+v) = nil error, want error", tt.cfg)
			}
		})
	}
}

func TestCompileDetectorsDefaults(t *testing.T) {
	dets, err := CompileDetectors([]DetectorConfig{{
		Name:     "d",
		Keywords: []string{"AcMe", "Hog"},
		Regex:    map[string]string{"zeta": `z`, "alpha": `a`},
	}})
	if err != nil {
		t.Fatalf("CompileDetectors: %v", err)
	}
	if len(dets) != 1 {
		t.Fatalf("got %d detectors, want 1", len(dets))
	}
	d := dets[0]

	// Keywords are lowercased for case-insensitive matching.
	if d.Keywords[0] != "acme" || d.Keywords[1] != "hog" {
		t.Errorf("keywords not lowercased: %v", d.Keywords)
	}

	// Regexes are sorted by name so iteration/primary selection is deterministic.
	if d.Regexes[0].Name != "alpha" || d.Regexes[1].Name != "zeta" {
		t.Errorf("regexes not sorted by name: %v, %v", d.Regexes[0].Name, d.Regexes[1].Name)
	}

	// Primary defaults to the first (alphabetical) regex.
	if d.Primary != d.Regexes[0].Regex {
		t.Errorf("primary did not default to first regex")
	}
}

func TestDetectValuePatternsCustom(t *testing.T) {
	detectors, err := CompileDetectors([]DetectorConfig{
		{
			Name:     "acme-key",
			Keywords: []string{"acme"},
			Regex:    map[string]string{"token": `AKME-[0-9a-f]{16}`},
		},
		{
			Name:                "acme-strict",
			Keywords:            []string{"strict"},
			Regex:               map[string]string{"v": `STRICT-([A-Za-z0-9]+)`},
			Entropy:             3.0,
			ExcludeRegexesMatch: []string{`^STRICT-0+$`},
			ExcludeWords:        []string{"example"},
		},
		{
			Name:             "multi",
			Keywords:         []string{"multi"},
			Regex:            map[string]string{"a": `foo[0-9]{3}`, "b": `bar[0-9]{3}`},
			PrimaryRegexName: "a",
		},
	})
	if err != nil {
		t.Fatalf("CompileDetectors: %v", err)
	}
	set := RuleSet{Detectors: detectors}

	tests := []struct {
		name       string
		key        string
		value      string
		wantReason string // "" means no finding
	}{
		{"keyword in key fires", "acme_token", "AKME-0123456789abcdef", "custom:acme-key"},
		{"keyword absent does not fire", "token", "AKME-0123456789abcdef", ""},
		{"regex mismatch does not fire", "acme_token", "AKME-xyz", ""},
		{"high-entropy capture fires", "strict", "STRICT-Ab3Df9Gh2Jk5Lm8Qp", "custom:acme-strict"},
		{"low-entropy capture suppressed", "strict", "STRICT-aaaaaaaaaaaaaaaa", ""},
		{"exclude regex suppresses", "strict", "STRICT-0000000000", ""},
		{"exclude word suppresses", "strict_example", "STRICT-Ab3Df9Gh2Jk5Lm8Qp", ""},
		{"multi-regex all match fires", "multi", "foo123 bar456", "custom:multi"},
		{"multi-regex partial does not fire", "multi", "foo123 only", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := detectValuePatterns("f", "$.x", tt.key, tt.value, set)

			if tt.wantReason == "" {
				if len(findings) != 0 {
					t.Fatalf("expected no finding, got %+v", findings)
				}
				return
			}

			if len(findings) != 1 {
				t.Fatalf("expected one finding, got %+v", findings)
			}
			if findings[0].Reason != tt.wantReason {
				t.Errorf("reason = %q, want %q", findings[0].Reason, tt.wantReason)
			}
		})
	}
}

func TestDetectValuePatternsGitleaksPrecedence(t *testing.T) {
	// A custom detector that also matches an AWS key shape must not shadow the
	// built-in gitleaks rule: the built-in match wins.
	detectors, err := CompileDetectors([]DetectorConfig{{
		Name:     "my-aws",
		Keywords: []string{"akia"},
		Regex:    map[string]string{"v": `AKIA[A-Z2-7]{16}`},
	}})
	if err != nil {
		t.Fatalf("CompileDetectors: %v", err)
	}

	findings := detectValuePatterns("f", "$.x", "AKIA", "AKIAIOSFODNN7EXAMPLE", RuleSet{Detectors: detectors})
	if len(findings) != 1 || findings[0].Reason != "gitleaks:aws-access-token" {
		t.Fatalf("expected gitleaks precedence, got %+v", findings)
	}
}

func TestDetectValuePatternsCustomSuppressedByRule(t *testing.T) {
	// A rule's ignore prefix suppresses custom-detector matches too.
	rules, err := CompileRules([]RuleConfig{{
		NameRegexes:         []NameRegexEntry{{Regex: `(?i)secret`}},
		IgnoreValuePrefixes: []string{"AKME-"},
	}})
	if err != nil {
		t.Fatalf("CompileRules: %v", err)
	}
	detectors, err := CompileDetectors([]DetectorConfig{{
		Name:     "acme-key",
		Keywords: []string{"acme"},
		Regex:    map[string]string{"token": `AKME-[0-9a-f]{16}`},
	}})
	if err != nil {
		t.Fatalf("CompileDetectors: %v", err)
	}

	findings := detectValuePatterns("f", "$.x", "acme_token", "AKME-0123456789abcdef", RuleSet{Rules: rules, Detectors: detectors})
	if len(findings) != 0 {
		t.Errorf("ignore prefix should suppress custom-detector finding, got %+v", findings)
	}
}

// TestCustomDetectorEndToEnd confirms detectors thread all the way through a
// real format detector, not just the value-pattern helper.
func TestCustomDetectorEndToEnd(t *testing.T) {
	set, err := CompileConfig(Config{
		Detectors: []DetectorConfig{{
			Name:     "acme-key",
			Keywords: []string{"acme"},
			Regex:    map[string]string{"token": `AKME-[0-9a-f]{16}`},
		}},
	})
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}

	content := strings.Join([]string{
		"ACME_TOKEN=AKME-0123456789abcdef",
		"OTHER=nothing to see here",
	}, "\n")

	findings := DotenvDetector{}.Detect("app.env", []byte(content), set)
	if len(findings) != 1 || findings[0].Reason != "custom:acme-key" {
		t.Fatalf("expected one custom:acme-key finding, got %+v", findings)
	}
}

// TestDetectValuePatternsHighEntropy confirms the generic high-entropy detector
// fires through detectValuePatterns, stays subordinate to the built-in gitleaks
// patterns, and honors rule suppression.
func TestDetectValuePatternsHighEntropy(t *testing.T) {
	rules, err := CompileRules([]RuleConfig{{
		NameRegexes:          []NameRegexEntry{{Regex: `(?i)secret`}},
		HighEntropyThreshold: 4.0,
		IgnoreValuePrefixes:  []string{"ignore-"},
	}})
	if err != nil {
		t.Fatalf("CompileRules: %v", err)
	}
	set := RuleSet{Rules: rules}

	// A high-entropy value with an unremarkable key name is flagged by entropy.
	findings := detectValuePatterns("f", "$.x", "anything", "Xa9Kd2Lp7Qm4Zr8Wb3Nc6Vt1Hf5Jg0Ys", set)
	if len(findings) != 1 || !strings.HasPrefix(findings[0].Reason, "high_entropy:") {
		t.Fatalf("expected a high_entropy finding, got %+v", findings)
	}

	// A built-in gitleaks pattern still wins over the generic entropy detector.
	findings = detectValuePatterns("f", "$.x", "anything", "AKIAIOSFODNN7EXAMPLE", set)
	if len(findings) != 1 || findings[0].Reason != "gitleaks:aws-access-token" {
		t.Fatalf("expected gitleaks precedence, got %+v", findings)
	}

	// A rule's ignore prefix suppresses the entropy match too.
	findings = detectValuePatterns("f", "$.x", "anything", "ignore-Xa9Kd2Lp7Qm4Zr8Wb3Nc6Vt1Hf5Jg0Ys", set)
	if len(findings) != 0 {
		t.Errorf("ignore prefix should suppress high-entropy finding, got %+v", findings)
	}
}

// TestNewFindingEntropy confirms every finding carries the rounded Shannon
// entropy of its value.
func TestNewFindingEntropy(t *testing.T) {
	// "abcd": four equally likely symbols => exactly 2.0 bits/symbol.
	f := newFinding("f", "$.x", "n", "v", "key", `"abcd"`, "test")
	if math.Abs(f.Entropy-2.0) > 1e-9 {
		t.Errorf("Entropy = %v, want 2.0", f.Entropy)
	}

	// Rounded to two decimals.
	got := valueEntropy("abcdefg")
	if math.Abs(got-math.Round(got*100)/100) > 1e-9 {
		t.Errorf("valueEntropy not rounded to 2 decimals: %v", got)
	}
}

func TestShannonEntropy(t *testing.T) {
	if got := shannonEntropy(""); got != 0 {
		t.Errorf("entropy(\"\") = %v, want 0", got)
	}
	if got := shannonEntropy("aaaa"); got != 0 {
		t.Errorf("entropy(\"aaaa\") = %v, want 0", got)
	}
	// Four equally likely symbols carry exactly 2 bits/symbol.
	if got := shannonEntropy("abcd"); math.Abs(got-2.0) > 1e-9 {
		t.Errorf("entropy(\"abcd\") = %v, want 2", got)
	}
}
