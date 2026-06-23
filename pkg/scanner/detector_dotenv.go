package scanner

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/joho/godotenv"
)

var envKeyValueRe = regexp.MustCompile(`^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.]*)\s*=\s*(.*?)\s*$`)

// DotenvDetector handles dotenv-style files (.env and its variants). It parses
// with joho/godotenv and falls back to line-based scanning for input that
// doesn't parse cleanly, mirroring the JSON/YAML detectors.
type DotenvDetector struct{}

func (DotenvDetector) Detect(file string, data []byte, rules []Rule) []Finding {
	root, err := parseDotenv(data)
	if err != nil {
		return detectEnvLines(file, data, rules)
	}

	return detectStructured(file, root, rules)
}

// parseDotenv loads dotenv bytes into a flat map for detectStructured. godotenv
// resolves quoting, "export" prefixes, and inline comments, and expands
// "$VAR"/"${VAR}" references against keys defined earlier in the same file (it
// does not read the process environment, so scanning can't leak ambient env).
func parseDotenv(data []byte) (map[string]any, error) {
	env, err := godotenv.UnmarshalBytes(data)
	if err != nil {
		return nil, err
	}

	root := make(map[string]any, len(env))
	for k, v := range env {
		root[k] = v
	}

	return root, nil
}

func detectEnvLines(file string, data []byte, rules []Rule) []Finding {
	var findings []Finding
	lines := strings.Split(string(data), "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)

		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		m := envKeyValueRe.FindStringSubmatch(line)
		if len(m) != 3 {
			continue
		}

		key := strings.TrimSpace(m[1])
		value := cleanEnvScalar(m[2])

		for _, rule := range rules {
			if !nameSignalsSecret(key, rule) {
				continue
			}

			if shouldSkipValue(value, rule) {
				continue
			}

			reason := classifySecretReason(value)
			if reason == "" && !isLikelySecretValue(value, rule.MinValueLen) {
				continue
			}
			if reason == "" {
				reason = "env key indicates secret and scalar value is populated"
			}

			findings = append(findings, newFinding(
				file,
				fmt.Sprintf("line:%d", i+1),
				"env_key",
				"env_value",
				key,
				value,
				reason,
			))
		}

		findings = append(findings, detectValuePatterns(file, fmt.Sprintf("line:%d", i+1), key, value, rules)...)
	}

	return findings
}

// cleanEnvScalar extracts the effective value from the right-hand side of a
// dotenv assignment. A fully quoted value keeps its contents verbatim (an inline
// "#" inside quotes is part of the value); an unquoted value has any trailing
// " #" comment stripped, mirroring how dotenv parsers treat comments.
func cleanEnvScalar(s string) string {
	s = strings.TrimSpace(s)

	if len(s) >= 2 {
		first, last := s[0], s[len(s)-1]
		if (first == '"' && last == '"') || (first == '\'' && last == '\'') {
			return s[1 : len(s)-1]
		}
	}

	if idx := strings.Index(s, " #"); idx >= 0 {
		s = strings.TrimSpace(s[:idx])
	}

	return normalizeScalar(s)
}
