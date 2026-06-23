package scanner

import "testing"

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
			NameRegex:           `(?i)secret`,
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
		if rule.NameRegex == nil || !rule.NameRegex.MatchString("client_secret") {
			t.Errorf("NameRegex did not compile/match as expected")
		}
		if len(rule.IgnoreNamePatterns) != 1 || len(rule.IgnoreValuePatterns) != 1 {
			t.Errorf("ignore patterns not compiled: %+v", rule)
		}
	})

	t.Run("explicit min length is preserved", func(t *testing.T) {
		rules, err := CompileRules([]RuleConfig{{NameRegex: `x`, MinValueLen: 16}})
		if err != nil {
			t.Fatalf("compileRules: %v", err)
		}
		if rules[0].MinValueLen != 16 {
			t.Errorf("MinValueLen = %d, want 16", rules[0].MinValueLen)
		}
	})

	t.Run("invalid name_regex returns error", func(t *testing.T) {
		if _, err := CompileRules([]RuleConfig{{NameRegex: `([`}}); err == nil {
			t.Error("expected error for invalid name_regex, got nil")
		}
	})

	t.Run("invalid ignore_value_pattern returns error", func(t *testing.T) {
		if _, err := CompileRules([]RuleConfig{{NameRegex: `x`, IgnoreValuePatterns: []string{`([`}}}); err == nil {
			t.Error("expected error for invalid ignore_value_pattern, got nil")
		}
	})

	t.Run("invalid ignore_name_pattern returns error", func(t *testing.T) {
		if _, err := CompileRules([]RuleConfig{{NameRegex: `x`, IgnoreNamePatterns: []string{`([`}}}); err == nil {
			t.Error("expected error for invalid ignore_name_pattern, got nil")
		}
	})
}
