package scanner

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestScanFilePopulatesLangLineLevel(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.ini")
	content := "[creds]\naws_key=AKIAIOSFODNN7EXAMPLE\nendpoint=https://abc123.lambda-url.us-east-1.on.aws/\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	rules, err := CompileRules([]RuleConfig{{NameRegexes: []NameRegexEntry{{Regex: `(?i)key`}}}})
	if err != nil {
		t.Fatalf("CompileRules: %v", err)
	}

	findings, err := ScanFile(path, RuleSet{Rules: rules}, ScanOptions{})
	if err != nil {
		t.Fatalf("ScanFile: %v", err)
	}

	byName := map[string]Finding{}
	for _, f := range findings {
		byName[f.Name] = f
	}

	// The Lang field replaces the former "lang:" tag, so it must not reappear there.
	secret, ok := byName["aws_key"]
	if !ok {
		t.Fatalf("aws_key finding missing: %+v", findings)
	}
	if secret.Level != levelHigh || secret.Lang != "ini" {
		t.Errorf("secret: level=%q lang=%q, want high/ini", secret.Level, secret.Lang)
	}
	if hasTag(secret.Tags, "lang:ini") {
		t.Errorf("lang must be carried in the Lang field, not a tag: %v", secret.Tags)
	}

	info, ok := byName["endpoint"]
	if !ok {
		t.Fatalf("endpoint info finding missing: %+v", findings)
	}
	if info.Level != levelInfo || info.Reason != "info:aws-lambda-url" || info.Lang != "ini" {
		t.Errorf("info: level=%q reason=%q lang=%q, want info/info:aws-lambda-url/ini", info.Level, info.Reason, info.Lang)
	}
}

func TestNameRegexesSchema(t *testing.T) {
	t.Run("parses string and dict entries from YAML", func(t *testing.T) {
		var cfg Config
		src := `
rules:
  - name_regexes:
      - '(?i)secret'
      - name: camelcase-key
        regex: '(?-i:[a-z0-9]Key([A-Z0-9_]|$))'
`
		if err := yaml.Unmarshal([]byte(src), &cfg); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}

		entries := cfg.Rules[0].NameRegexes
		if len(entries) != 2 {
			t.Fatalf("got %d entries, want 2", len(entries))
		}
		if entries[0].Name != "" || entries[0].Regex != `(?i)secret` {
			t.Errorf("string entry = %+v, want unnamed (?i)secret", entries[0])
		}
		if entries[1].Name != "camelcase-key" || entries[1].Regex == "" {
			t.Errorf("dict entry = %+v, want named camelcase-key", entries[1])
		}
	})

	t.Run("a name matching any pattern signals a secret", func(t *testing.T) {
		rules, err := CompileRules([]RuleConfig{{
			NameRegexes: []NameRegexEntry{
				{Regex: `(?i)password`},
				{Regex: `(?i)secret`},
				{Name: "camelcase-key", Regex: `(?-i:[a-z0-9]Key([A-Z0-9_]|$))`},
			},
			IgnoreNamePatterns: []string{`(?i)label`},
		}})
		if err != nil {
			t.Fatalf("compileRules: %v", err)
		}

		rule := rules[0]
		if len(rule.NameRegexes) != 3 {
			t.Fatalf("got %d compiled patterns, want 3", len(rule.NameRegexes))
		}

		for _, name := range []string{"password", "client_secret", "functionKey"} {
			if !nameSignalsSecret(name, rule) {
				t.Errorf("nameSignalsSecret(%q) = false, want true", name)
			}
		}
		for _, name := range []string{"monkey", "keyboard", "displayName", "labelKey"} {
			if nameSignalsSecret(name, rule) {
				t.Errorf("nameSignalsSecret(%q) = true, want false", name)
			}
		}
	})

	t.Run("invalid regex in name_regexes returns error", func(t *testing.T) {
		if _, err := CompileRules([]RuleConfig{{NameRegexes: []NameRegexEntry{{Regex: `([`}}}}); err == nil {
			t.Error("expected error for invalid name_regexes entry, got nil")
		}
	})
}

func TestIsEnvFile(t *testing.T) {
	tests := map[string]bool{
		".env":            true,
		"/app/.env":       true,
		".env.local":      true,
		".env.production": true,
		"config.env":      true,
		"dir/service.env": true,
		"service.json":    false,
		"values.yaml":     false,
		"environment.txt": false,
		"env":             false,
		".environment":    false,
	}

	for path, want := range tests {
		if got := isEnvFile(path); got != want {
			t.Errorf("isEnvFile(%q) = %v, want %v", path, got, want)
		}
	}
}

func TestCompileRules(t *testing.T) {
	t.Run("compiles patterns and defaults min length", func(t *testing.T) {
		rules, err := CompileRules([]RuleConfig{{
			NameRegexes:         []NameRegexEntry{{Regex: `(?i)secret`}},
			IgnoreNamePatterns:  []string{`(?i)label`},
			IgnoreValuePatterns: []string{`^ENC\[.*\]$`},
		}})
		if err != nil {
			t.Fatalf("compileRules: %v", err)
		}

		if len(rules) != 1 {
			t.Fatalf("got %d rules, want 1", len(rules))
		}

		rule := rules[0]
		if rule.MinValueLen != 8 {
			t.Errorf("MinValueLen = %d, want default 8", rule.MinValueLen)
		}
		if !matchesAnyNameRegex("client_secret", rule) {
			t.Errorf("name pattern did not compile/match as expected")
		}
		if len(rule.IgnoreNamePatterns) != 1 || len(rule.IgnoreValuePatterns) != 1 {
			t.Errorf("ignore patterns not compiled: %+v", rule)
		}
	})

	t.Run("explicit min length is preserved", func(t *testing.T) {
		rules, err := CompileRules([]RuleConfig{{NameRegexes: []NameRegexEntry{{Regex: `x`}}, MinValueLen: 16}})
		if err != nil {
			t.Fatalf("compileRules: %v", err)
		}
		if rules[0].MinValueLen != 16 {
			t.Errorf("MinValueLen = %d, want 16", rules[0].MinValueLen)
		}
	})

	t.Run("invalid name pattern returns error", func(t *testing.T) {
		if _, err := CompileRules([]RuleConfig{{NameRegexes: []NameRegexEntry{{Regex: `([`}}}}); err == nil {
			t.Error("expected error for invalid name pattern, got nil")
		}
	})

	t.Run("invalid ignore_value_pattern returns error", func(t *testing.T) {
		if _, err := CompileRules([]RuleConfig{{NameRegexes: []NameRegexEntry{{Regex: `x`}}, IgnoreValuePatterns: []string{`([`}}}); err == nil {
			t.Error("expected error for invalid ignore_value_pattern, got nil")
		}
	})

	t.Run("invalid ignore_name_pattern returns error", func(t *testing.T) {
		if _, err := CompileRules([]RuleConfig{{NameRegexes: []NameRegexEntry{{Regex: `x`}}, IgnoreNamePatterns: []string{`([`}}}); err == nil {
			t.Error("expected error for invalid ignore_name_pattern, got nil")
		}
	})
}
