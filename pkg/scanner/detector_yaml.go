package scanner

import (
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

var yamlKeyValueRe = regexp.MustCompile(`^\s*([A-Za-z0-9_.-]+)\s*:\s*(.+?)\s*$`)

// YAMLDetector handles .yaml/.yml files, falling back to line-based scanning for
// templated YAML that doesn't parse cleanly.
type YAMLDetector struct{}

func (YAMLDetector) Detect(file string, data []byte, set RuleSet) []Finding {
	var root any
	if err := yaml.Unmarshal(data, &root); err != nil {
		return detectYAMLLines(file, data, set)
	}

	return detectStructured(file, root, set)
}

func detectYAMLLines(file string, data []byte, set RuleSet) []Finding {
	var findings []Finding
	lang := languageName(file)
	lines := strings.Split(string(data), "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)

		if trimmed == "" ||
			strings.HasPrefix(trimmed, "#") ||
			strings.HasPrefix(trimmed, "{{") ||
			strings.HasPrefix(trimmed, "-}}") {
			continue
		}

		m := yamlKeyValueRe.FindStringSubmatch(line)
		if len(m) != 3 {
			continue
		}

		key := strings.TrimSpace(m[1])
		value := cleanYamlScalar(m[2])

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
				reason = "templated YAML key indicates secret and scalar value is populated"
			}

			findings = append(findings, newFinding(
				file,
				fmt.Sprintf("line:%d", i+1),
				"yaml_key",
				"yaml_value",
				key,
				value,
				reason,
			))
		}

		findings = append(findings, detectValuePatterns(ExaminationFocus{File: file, Path: fmt.Sprintf("line:%d", i+1), Name: key, Value: value, PrevFindings: recentFindings(findings, set.prevWindow())}, set)...)
	}

	return findings
}

func cleanYamlScalar(s string) string {
	s = strings.TrimSpace(s)

	if idx := strings.Index(s, " #"); idx >= 0 {
		s = strings.TrimSpace(s[:idx])
	}

	return normalizeScalar(s)
}
