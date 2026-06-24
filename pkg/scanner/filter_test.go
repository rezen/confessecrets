package scanner

import (
	"strings"
	"testing"
)

func TestCompileFilterErrors(t *testing.T) {
	tests := []struct {
		name string
		expr string
	}{
		{"syntax error", `entropy <=`},
		{"unknown variable", `bogus > 1`},
		{"non-boolean result", `entropy + 1`},
		{"type mismatch", `name > 4`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := compileFilter(tt.expr); err == nil {
				t.Errorf("compileFilter(%q) = nil error, want error", tt.expr)
			}
		})
	}
}

func TestCompileFilterEmpty(t *testing.T) {
	for _, s := range []string{"", "   "} {
		f, err := compileFilter(s)
		if err != nil {
			t.Fatalf("compileFilter(%q): %v", s, err)
		}
		if f != nil {
			t.Errorf("compileFilter(%q) = %v, want nil (no filtering)", s, f)
		}
	}
}

func TestFilterExcludes(t *testing.T) {
	f, err := compileFilter(`entropy <= 4 && name_value_similarity > 0.65`)
	if err != nil {
		t.Fatalf("compileFilter: %v", err)
	}

	tests := []struct {
		name    string
		finding Finding
		want    bool
	}{
		{"low entropy near-echo dropped", Finding{Entropy: 3.5, NameValueSimilarity: 0.7}, true},
		{"high entropy kept", Finding{Entropy: 4.8, NameValueSimilarity: 0.7}, false},
		{"dissimilar kept", Finding{Entropy: 3.5, NameValueSimilarity: 0.4}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := f.Excludes(tt.finding)
			if err != nil {
				t.Fatalf("Excludes: %v", err)
			}
			if got != tt.want {
				t.Errorf("Excludes(%+v) = %v, want %v", tt.finding, got, tt.want)
			}
		})
	}
}

func TestFilterStringBuiltins(t *testing.T) {
	f, err := compileFilter(`value matches "(?i)example$" || reason startsWith "gitleaks:"`)
	if err != nil {
		t.Fatalf("compileFilter: %v", err)
	}

	for _, tt := range []struct {
		finding Finding
		want    bool
	}{
		{Finding{RawValue: "AKIAIOSFODNN7EXAMPLE"}, true},
		{Finding{Reason: "gitleaks:aws-access-token"}, true},
		{Finding{RawValue: "Xk9mQ2vLp7", Reason: "map key indicates secret"}, false},
	} {
		got, err := f.Excludes(tt.finding)
		if err != nil {
			t.Fatalf("Excludes: %v", err)
		}
		if got != tt.want {
			t.Errorf("Excludes(%+v) = %v, want %v", tt.finding, got, tt.want)
		}
	}
}

func TestApplyFilterNil(t *testing.T) {
	in := []Finding{{Name: "a"}, {Name: "b"}}
	out, err := applyFilter(in, nil, false)
	if err != nil {
		t.Fatalf("applyFilter: %v", err)
	}
	if len(out) != 2 {
		t.Errorf("nil filter changed findings: got %d, want 2", len(out))
	}
}

// TestApplyFilterIncludeFiltered confirms that, with includeFiltered set, excluded
// findings are retained and annotated rather than dropped.
func TestApplyFilterIncludeFiltered(t *testing.T) {
	filter, err := compileFilter(`name == "drop"`)
	if err != nil {
		t.Fatalf("compileFilter: %v", err)
	}

	in := []Finding{{Name: "keep"}, {Name: "drop"}}

	// Default: the matching finding is dropped.
	dropped, err := applyFilter(in, filter, false)
	if err != nil {
		t.Fatalf("applyFilter: %v", err)
	}
	if len(dropped) != 1 || dropped[0].Name != "keep" {
		t.Fatalf("default filter should drop the match, got %+v", dropped)
	}

	// With includeFiltered: both retained, the match annotated.
	in = []Finding{{Name: "keep"}, {Name: "drop"}}
	kept, err := applyFilter(in, filter, true)
	if err != nil {
		t.Fatalf("applyFilter: %v", err)
	}
	if len(kept) != 2 {
		t.Fatalf("includeFiltered should retain all findings, got %d", len(kept))
	}
	for _, f := range kept {
		switch f.Name {
		case "keep":
			if f.Filtered || f.FilteredReason != "" {
				t.Errorf("non-matching finding wrongly marked filtered: %+v", f)
			}
		case "drop":
			if !f.Filtered || f.FilteredReason != `name == "drop"` {
				t.Errorf("matching finding not annotated: %+v", f)
			}
		}
	}
}

// TestFilterEndToEnd confirms the filter drops findings through CompileConfig and
// a real format detector.
func TestFilterEndToEnd(t *testing.T) {
	set, err := CompileConfig(Config{
		Rules: []RuleConfig{{
			NameRegexes: []NameRegexEntry{{Regex: `(?i)(secret|password|token)`}},
			MinValueLen: 8,
		}},
		Filter: `lower(name) == "password"`,
	})
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}

	content := strings.Join([]string{
		"PASSWORD=Xk9$mQ2vLp7wRt4z",
		"SECRET=Zr8Wb3Nc6Vt1Hf5Jg0Ys",
	}, "\n")

	findings := mustFilter(t, DotenvDetector{}.Detect("app.env", []byte(content), set), set.Filter)
	for _, f := range findings {
		if strings.EqualFold(f.Name, "password") {
			t.Errorf("filter should have dropped the PASSWORD finding, got %+v", f)
		}
	}
	if len(findings) == 0 {
		t.Errorf("expected the SECRET finding to survive the filter")
	}
}

func mustFilter(t *testing.T, findings []Finding, filter *Filter) []Finding {
	t.Helper()
	out, err := applyFilter(findings, filter, false)
	if err != nil {
		t.Fatalf("applyFilter: %v", err)
	}
	return out
}
