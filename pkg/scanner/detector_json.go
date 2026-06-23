package scanner

import (
	"fmt"
	"regexp"
	"strings"
)

var jsonishKVRe = regexp.MustCompile(
	`["']?([A-Za-z0-9_.-]*(secret|token|password|passwd|pwd|key|credential)[A-Za-z0-9_.-]*)["']?\s*[:=]\s*["']([^"']{8,})["']`,
)

// JSONDetector handles .json/.jsonc files. It parses structurally when possible
// and falls back to line-based scanning for non-standard JSON.
type JSONDetector struct{}

func (JSONDetector) Detect(file string, data []byte, rules []Rule) []Finding {
	var root any
	if err := parseFlexibleJSON(data, &root); err != nil {
		return detectJSONLines(file, data, rules)
	}

	return detectStructured(file, root, rules)
}

func detectJSONLines(file string, data []byte, rules []Rule) []Finding {
	var findings []Finding
	lines := strings.Split(string(data), "\n")

	for i, line := range lines {
		for _, match := range jsonishKVRe.FindAllStringSubmatch(line, -1) {
			key := match[1]
			value := match[3]

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
					reason = "JSON-like key indicates secret and scalar value is populated"
				}

				findings = append(findings, newFinding(
					file,
					fmt.Sprintf("line:%d", i+1),
					"jsonish_key",
					"jsonish_value",
					key,
					value,
					reason,
				))
			}

			findings = append(findings, detectValuePatterns(file, fmt.Sprintf("line:%d", i+1), key, value, rules)...)
		}
	}

	return findings
}
