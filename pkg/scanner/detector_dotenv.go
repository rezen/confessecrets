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

func (DotenvDetector) Detect(file string, data []byte, set RuleSet) []Finding {
	root, err := parseDotenv(data)
	if err != nil {
		return detectEnvLines(file, data, set)
	}

	return detectStructured(file, root, dotenvLineIndex(data), set)
}

// dotenvLineIndex maps each variable's structured path ("$.<key>") to the 1-based
// source line of its assignment, so detectStructured can order and annotate
// findings by line.
func dotenvLineIndex(data []byte) map[string]int {
	index := map[string]int{}
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

		index[joinPath("$", strings.TrimSpace(m[1]))] = i + 1
	}

	return index
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

func detectEnvLines(file string, data []byte, set RuleSet) []Finding {
	var findings []Finding
	lang := languageName(file)
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

		for _, rule := range set.Rules {
			if !nameSignalsSecret(key, rule) {
				continue
			}

			if shouldSkipValue(value, rule, lang) {
				continue
			}

			reason := classifySecretReason(value)
			if reason == "" && !isLikelySecretValue(key, value, rule, lang) {
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

		findings = append(findings, detectValuePatterns(ExaminationFocus{File: file, Path: fmt.Sprintf("line:%d", i+1), Name: key, Value: value, PrevFindings: recentFindings(findings, set.prevWindow())}, set)...)
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
