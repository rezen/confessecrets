package scanner

import (
	"fmt"
	"strings"

	"gopkg.in/ini.v1"
)

// INIDetector handles INI-style files (sections plus key=value pairs). It parses
// structurally with go-ini and falls back to line-based scanning for files that
// don't parse cleanly, mirroring the JSON/YAML detectors.
type INIDetector struct{}

func (INIDetector) Detect(file string, data []byte, set RuleSet) []Finding {
	root, err := parseINI(data)
	if err != nil {
		return detectINILines(file, data, set)
	}

	return detectStructured(file, root, set)
}

// parseINI loads INI bytes into a nested map: the default section's keys sit at
// the top level and each named section becomes a sub-map, so detectStructured
// can walk it like any other structured document.
func parseINI(data []byte) (map[string]any, error) {
	cfg, err := ini.Load(data)
	if err != nil {
		return nil, err
	}

	root := map[string]any{}
	for _, section := range cfg.Sections() {
		target := root
		if name := section.Name(); name != ini.DefaultSection {
			sub := map[string]any{}
			root[name] = sub
			target = sub
		}

		for _, key := range section.Keys() {
			target[key.Name()] = key.Value()
		}
	}

	return root, nil
}

// detectINILines scans an INI-style file. It tracks the current [section] for
// context, treats ';' and '#' as comment markers, and splits each entry on the
// first '=' or ':'. Surrounding quotes on a value are stripped.
func detectINILines(file string, data []byte, set RuleSet) []Finding {
	var findings []Finding
	lines := strings.Split(string(data), "\n")
	section := ""

	for i, line := range lines {
		trimmed := strings.TrimSpace(strings.TrimRight(line, "\r"))

		if trimmed == "" || trimmed[0] == ';' || trimmed[0] == '#' {
			continue
		}

		if trimmed[0] == '[' && strings.HasSuffix(trimmed, "]") {
			section = strings.TrimSpace(trimmed[1 : len(trimmed)-1])
			continue
		}

		key, value, ok := splitINIPair(trimmed)
		if !ok {
			continue
		}

		path := iniLocation(section, i+1)

		for _, rule := range set.Rules {
			if !nameSignalsSecret(key, rule) {
				continue
			}

			if shouldSkipValue(value, rule) {
				continue
			}

			reason := classifySecretReason(value)
			if reason == "" && !isLikelySecretValue(key, value, rule) {
				continue
			}
			if reason == "" {
				reason = "ini key indicates secret and value is populated"
			}

			findings = append(findings, newFinding(
				file,
				path,
				"ini_key",
				"ini_value",
				key,
				value,
				reason,
			))
		}

		findings = append(findings, detectValuePatterns(ExaminationFocus{File: file, Path: path, Name: key, Value: value, PrevFindings: recentFindings(findings, set.prevWindow())}, set)...)
	}

	return findings
}

// splitINIPair divides an INI entry into key and value at the first '=' or ':'.
// ok is false when there is no separator or the key is empty.
func splitINIPair(line string) (key, value string, ok bool) {
	idx := strings.IndexAny(line, "=:")
	if idx <= 0 {
		return "", "", false
	}

	key = strings.TrimSpace(line[:idx])
	if key == "" {
		return "", "", false
	}

	return key, cleanINIScalar(line[idx+1:]), true
}

// cleanINIScalar trims an INI value and removes one layer of surrounding
// matching quotes.
func cleanINIScalar(s string) string {
	s = strings.TrimSpace(s)

	if len(s) >= 2 {
		first, last := s[0], s[len(s)-1]
		if (first == '"' && last == '"') || (first == '\'' && last == '\'') {
			return s[1 : len(s)-1]
		}
	}

	return s
}

// iniLocation builds the finding location, qualifying the line with its section
// when one is in scope.
func iniLocation(section string, line int) string {
	if section == "" {
		return fmt.Sprintf("line:%d", line)
	}
	return fmt.Sprintf("[%s] line:%d", section, line)
}
