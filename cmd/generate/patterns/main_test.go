package main

import "testing"

func TestLeadingLiteral(t *testing.T) {
	tests := []struct {
		regex string
		want  string
	}{
		// Distinctive fixed prefixes survive wrapper stripping.
		{`\bghp_[0-9a-zA-Z]{36}\b`, "ghp_"},
		{`\bglpat-[\w-]{20}\b`, "glpat-"},
		{`\b(ABSK[A-Za-z0-9+/]{109,269})`, "ABSK"},
		{`(?i)\b(glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8})`, "glsa_"},
		// A leading literal alternative is reached through the group opener.
		{`\b((?:A3T[A-Z0-9]|AKIA|ASIA)[A-Z2-7]{16})\b`, "A3T"},
		// Named group opener is stripped.
		{`\b(?P<token>shpat_[a-fA-F0-9]{32})\b`, "shpat_"},
		// Key-context rules open with a class or optional run: no fixed prefix.
		{`(?i)[\w.-]{0,50}?(?:api|key)["']([0-9a-z]{32})["']`, ""},
		{`\b[a-z0-9]{32}\b`, ""},
	}

	for _, tt := range tests {
		if got := leadingLiteral(tt.regex); got != tt.want {
			t.Errorf("leadingLiteral(%q) = %q, want %q", tt.regex, got, tt.want)
		}
	}
}

func TestAdmit(t *testing.T) {
	tests := []struct {
		name string
		r    rule
		want string // "" means admitted
	}{
		{"distinctive prefix", rule{regex: `\bghp_[0-9a-zA-Z]{36}\b`}, ""},
		{"short prefix with digit", rule{regex: `\b(A3T[A-Z0-9]{16})\b`}, ""},
		{"generic keyword prefix", rule{regex: `\bsecret[0-9a-z]{32}\b`}, "generic-keyword-prefix"},
		{"too short", rule{regex: `\bab[0-9a-z]{32}\b`}, "prefix-too-short"},
		{"no fixed prefix", rule{regex: `\b[a-z0-9]{32}\b`}, "no-fixed-prefix"},
		{"empty regex", rule{regex: ``}, "no-regex"},
	}

	for _, tt := range tests {
		if got := admit(&tt.r, 4); got != tt.want {
			t.Errorf("%s: admit = %q, want %q", tt.name, got, tt.want)
		}
	}
}
