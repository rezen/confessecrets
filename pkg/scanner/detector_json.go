package scanner

import (
	"bytes"
	"encoding/json"
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

func (JSONDetector) Detect(file string, data []byte, set RuleSet) []Finding {
	// Standard JSON parses against the original bytes, so a position-aware decode
	// can recover exact line numbers. The relaxed fallbacks rewrite the input
	// (comment stripping, standardization), which invalidates offsets, so they run
	// without a line index and fall back to stable path ordering.
	clean := stripBOM(data)
	var root any
	if err := json.Unmarshal(clean, &root); err == nil {
		return detectStructured(file, root, jsonLineIndex(clean), set)
	}

	if err := parseFlexibleJSON(data, &root); err != nil {
		return detectJSONLines(file, data, set)
	}

	return detectStructured(file, root, nil, set)
}

// jsonLineIndex maps each value's structured path to its 1-based source line by
// streaming the document with an offset-tracking decoder. Paths follow the same
// "$.a.b" / "$.a[0]" convention as detectStructured's walk. Returns nil if the
// stream can't be fully tokenized.
func jsonLineIndex(data []byte) map[string]int {
	index := map[string]int{}
	lineAt := newLineMapper(data)
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()

	var walk func(path string) error
	walk = func(path string) error {
		tok, err := dec.Token()
		if err != nil {
			return err
		}

		if delim, ok := tok.(json.Delim); ok {
			index[path] = lineAt(dec.InputOffset())
			switch delim {
			case '{':
				for dec.More() {
					keyTok, err := dec.Token()
					if err != nil {
						return err
					}
					key, _ := keyTok.(string)
					if err := walk(joinPath(path, key)); err != nil {
						return err
					}
				}
			case '[':
				for i := 0; dec.More(); i++ {
					if err := walk(fmt.Sprintf("%s[%d]", path, i)); err != nil {
						return err
					}
				}
			}
			_, err := dec.Token() // consume the closing ] or }
			return err
		}

		index[path] = lineAt(dec.InputOffset())
		return nil
	}

	if err := walk("$"); err != nil {
		return nil
	}

	return index
}

func detectJSONLines(file string, data []byte, set RuleSet) []Finding {
	var findings []Finding
	lang := languageName(file)
	lines := strings.Split(string(data), "\n")

	for i, line := range lines {
		for _, match := range jsonishKVRe.FindAllStringSubmatch(line, -1) {
			key := match[1]
			value := match[3]

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

			findings = append(findings, detectValuePatterns(ExaminationFocus{File: file, Path: fmt.Sprintf("line:%d", i+1), Name: key, Value: value, PrevFindings: recentFindings(findings, set.prevWindow())}, set)...)
		}
	}

	return findings
}
