package scanner

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestFilterConfigSchema covers the YAML forms the filter list accepts: a bare
// scalar (default "filter" action), a single mapping, and a sequence mixing both.
func TestFilterConfigSchema(t *testing.T) {
	t.Run("bare scalar defaults to filter action", func(t *testing.T) {
		var cfg Config
		if err := yaml.Unmarshal([]byte(`filter: 'entropy <= 4'`), &cfg); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if len(cfg.Filter) != 1 {
			t.Fatalf("got %d entries, want 1", len(cfg.Filter))
		}
		got := cfg.Filter[0]
		if got.Filter != "entropy <= 4" || got.Action != filterActionFilter || got.ID != "" {
			t.Errorf("scalar entry = %+v, want unnamed filter-action", got)
		}
	})

	t.Run("sequence of scalars and mappings", func(t *testing.T) {
		var cfg Config
		src := `
filter:
  - 'entropy <= 4'
  - id: weak-echo
    action: tag
    filter: 'name_value_similarity > 0.65'
`
		if err := yaml.Unmarshal([]byte(src), &cfg); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if len(cfg.Filter) != 2 {
			t.Fatalf("got %d entries, want 2", len(cfg.Filter))
		}
		if cfg.Filter[0].Action != filterActionFilter {
			t.Errorf("scalar entry action = %q, want %q", cfg.Filter[0].Action, filterActionFilter)
		}
		tag := cfg.Filter[1]
		if tag.ID != "weak-echo" || tag.Action != filterActionTag || tag.Filter == "" {
			t.Errorf("mapping entry = %+v, want tag-action weak-echo", tag)
		}
	})

	t.Run("mapping without action defaults to filter", func(t *testing.T) {
		var cfg Config
		src := `
filter:
  - id: r1
    filter: 'entropy <= 4'
`
		if err := yaml.Unmarshal([]byte(src), &cfg); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if cfg.Filter[0].Action != filterActionFilter {
			t.Errorf("action = %q, want %q", cfg.Filter[0].Action, filterActionFilter)
		}
	})
}

// TestLanguageName checks the per-format language name derived from a file path.
func TestLanguageName(t *testing.T) {
	cases := map[string]string{
		"app.py":         "python",
		"main.go":        "go",
		"config.json":    "json",
		"settings.yaml":  "yaml",
		"web.config":     "xml",
		"app.properties": "properties",
		".env":           "dotenv",
		"app.env":        "dotenv",
		"notes.txt":      "",
	}
	for path, want := range cases {
		if got := languageName(path); got != want {
			t.Errorf("languageName(%q) = %q, want %q", path, got, want)
		}
	}
}

// compileFilter compiles a single filter-action expression for the tests,
// returning nil when the expression is empty.
func compileFilter(t *testing.T, source string) *Filter {
	t.Helper()
	filters, err := compileFilters([]FilterConfig{{Filter: source, Action: filterActionFilter}})
	if err != nil {
		t.Fatalf("compileFilters(%q): %v", source, err)
	}
	if len(filters) == 0 {
		return nil
	}
	return filters[0]
}

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
			if _, err := compileFilters([]FilterConfig{{Filter: tt.expr}}); err == nil {
				t.Errorf("compileFilters(%q) = nil error, want error", tt.expr)
			}
		})
	}
}

func TestCompileFilterEmpty(t *testing.T) {
	for _, s := range []string{"", "   "} {
		filters, err := compileFilters([]FilterConfig{{Filter: s}})
		if err != nil {
			t.Fatalf("compileFilters(%q): %v", s, err)
		}
		if len(filters) != 0 {
			t.Errorf("compileFilters(%q) = %v, want no filters", s, filters)
		}
	}
}

// TestCompileFilterTagRequiresID confirms a tag-action rule must carry an id, and
// that an unknown action is rejected.
func TestCompileFilterTagRequiresID(t *testing.T) {
	if _, err := compileFilters([]FilterConfig{{Action: filterActionTag, Filter: `entropy > 4`}}); err == nil {
		t.Errorf("tag action without id = nil error, want error")
	}
	if _, err := compileFilters([]FilterConfig{{Action: "bogus", Filter: `entropy > 4`}}); err == nil {
		t.Errorf("unknown action = nil error, want error")
	}
}

func TestFilterExcludes(t *testing.T) {
	f := compileFilter(t, `entropy <= 4 && name_value_similarity > 0.65`)

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
			got, err := f.Matches(tt.finding)
			if err != nil {
				t.Fatalf("Matches: %v", err)
			}
			if got != tt.want {
				t.Errorf("Matches(%+v) = %v, want %v", tt.finding, got, tt.want)
			}
		})
	}
}

func TestFilterStringBuiltins(t *testing.T) {
	f := compileFilter(t, `value matches "(?i)example$" || reason startsWith "sig:"`)

	for _, tt := range []struct {
		finding Finding
		want    bool
	}{
		{Finding{RawValue: "AKIAIOSFODNN7EXAMPLE"}, true},
		{Finding{Reason: "sig:aws-access-token"}, true},
		{Finding{RawValue: "Xk9mQ2vLp7", Reason: "map key indicates secret"}, false},
	} {
		got, err := f.Matches(tt.finding)
		if err != nil {
			t.Fatalf("Matches: %v", err)
		}
		if got != tt.want {
			t.Errorf("Matches(%+v) = %v, want %v", tt.finding, got, tt.want)
		}
	}
}

func TestApplyFilterNil(t *testing.T) {
	in := []Finding{{Name: "a"}, {Name: "b"}}
	out, err := applyFilters(in, nil, false)
	if err != nil {
		t.Fatalf("applyFilters: %v", err)
	}
	if len(out) != 2 {
		t.Errorf("nil filter changed findings: got %d, want 2", len(out))
	}
}

// TestApplyFilterTag confirms a tag-action rule keeps matches and labels them with
// the rule's id, leaving non-matches untouched.
func TestApplyFilterTag(t *testing.T) {
	filters, err := compileFilters([]FilterConfig{{ID: "weak", Action: filterActionTag, Filter: `entropy < 3`}})
	if err != nil {
		t.Fatalf("compileFilters: %v", err)
	}

	in := []Finding{{Name: "low", Entropy: 2}, {Name: "high", Entropy: 5}}
	out, err := applyFilters(in, filters, false)
	if err != nil {
		t.Fatalf("applyFilters: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("tag action dropped findings: got %d, want 2", len(out))
	}
	for _, f := range out {
		switch f.Name {
		case "low":
			if len(f.Tags) != 1 || f.Tags[0] != "weak" {
				t.Errorf("matching finding not tagged: %+v", f.Tags)
			}
		case "high":
			if len(f.Tags) != 0 {
				t.Errorf("non-matching finding wrongly tagged: %+v", f.Tags)
			}
		}
	}
}

// TestApplyFilterIncludeFiltered confirms that, with includeFiltered set, excluded
// findings are retained and annotated rather than dropped.
func TestApplyFilterIncludeFiltered(t *testing.T) {
	filter := compileFilter(t, `name == "drop"`)

	in := []Finding{{Name: "keep"}, {Name: "drop"}}

	// Default: the matching finding is dropped.
	dropped, err := applyFilters(in, []*Filter{filter}, false)
	if err != nil {
		t.Fatalf("applyFilters: %v", err)
	}
	if len(dropped) != 1 || dropped[0].Name != "keep" {
		t.Fatalf("default filter should drop the match, got %+v", dropped)
	}

	// With includeFiltered: both retained, the match annotated.
	in = []Finding{{Name: "keep"}, {Name: "drop"}}
	kept, err := applyFilters(in, []*Filter{filter}, true)
	if err != nil {
		t.Fatalf("applyFilters: %v", err)
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
		Filter: FilterConfigs{{Action: filterActionFilter, Filter: `lower(name) == "password"`}},
	})
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}

	content := strings.Join([]string{
		"PASSWORD=Xk9$mQ2vLp7wRt4z",
		"SECRET=Zr8Wb3Nc6Vt1Hf5Jg0Ys",
	}, "\n")

	findings := mustFilter(t, DotenvDetector{}.Detect("app.env", []byte(content), set), set.Filters)
	for _, f := range findings {
		if strings.EqualFold(f.Name, "password") {
			t.Errorf("filter should have dropped the PASSWORD finding, got %+v", f)
		}
	}
	if len(findings) == 0 {
		t.Errorf("expected the SECRET finding to survive the filter")
	}
}

func mustFilter(t *testing.T, findings []Finding, filters []*Filter) []Finding {
	t.Helper()
	out, err := applyFilters(findings, filters, false)
	if err != nil {
		t.Fatalf("applyFilters: %v", err)
	}
	return out
}
