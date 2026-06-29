package scanner

import (
	"bytes"
	"encoding/xml"
	"strings"
)

// XMLDetector handles .xml files via streaming token scanning.
type XMLDetector struct{}

func (XMLDetector) Detect(file string, data []byte, set RuleSet) []Finding {
	return detectXML(file, data, set)
}

func detectXML(file string, data []byte, set RuleSet) []Finding {
	var findings []Finding

	dec := xml.NewDecoder(bytes.NewReader(data))
	dec.Strict = false
	dec.AutoClose = xml.HTMLAutoClose
	dec.Entity = xml.HTMLEntity

	lineAt := newLineMapper(data)

	type frame struct {
		name string
		line int
		text strings.Builder
	}

	var stack []*frame

	pathOf := func() string {
		var b strings.Builder
		for _, f := range stack {
			b.WriteByte('/')
			b.WriteString(f.name)
		}
		return b.String()
	}

	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}

		switch t := tok.(type) {
		case xml.StartElement:
			line := lineAt(dec.InputOffset())
			stack = append(stack, &frame{name: t.Name.Local, line: line})

			before := len(findings)
			findings = append(findings, detectXMLAttrs(file, pathOf(), t.Attr, set.Rules)...)
			findings = append(findings, detectXMLAttrReasons(file, pathOf(), t.Attr, set.Rules)...)

			for _, attr := range t.Attr {
				findings = append(findings, detectValuePatterns(ExaminationFocus{File: file, Path: pathOf(), Name: attr.Name.Local, Value: attr.Value, PrevFindings: recentFindings(findings, set.prevWindow())}, set)...)
			}
			stampLine(findings[before:], line)

		case xml.CharData:
			if len(stack) > 0 {
				stack[len(stack)-1].text.Write(t)
			}

		case xml.EndElement:
			if len(stack) == 0 {
				continue
			}

			f := stack[len(stack)-1]
			path := pathOf()
			stack = stack[:len(stack)-1]

			text := strings.TrimSpace(f.text.String())
			if text == "" {
				continue
			}

			before := len(findings)
			findings = append(findings, detectXMLElementText(file, path, f.name, text, set.Rules)...)
			findings = append(findings, detectXMLTextReason(file, path, f.name, text, set.Rules)...)
			findings = append(findings, detectValuePatterns(ExaminationFocus{File: file, Path: path, Name: f.name, Value: text, PrevFindings: recentFindings(findings, set.prevWindow())}, set)...)
			stampLine(findings[before:], f.line)
		}
	}

	sortFindingsByLine(findings)
	return findings
}

// stampLine sets the source line on a batch of just-produced findings whose line
// is known from the streaming decoder rather than from their path.
func stampLine(findings []Finding, line int) {
	if line <= 0 {
		return
	}
	for i := range findings {
		findings[i].Line = line
	}
}

func detectXMLElementText(file, path, elem, text string, rules []Rule) []Finding {
	var findings []Finding
	lang := languageName(file)

	for _, rule := range rules {
		if !nameSignalsSecret(elem, rule) {
			continue
		}

		if shouldSkipValue(text, rule, lang) {
			continue
		}

		reason := classifySecretReason(text)
		if reason == "" && !isLikelySecretValue(elem, text, rule, lang) {
			continue
		}
		if reason == "" {
			reason = reasonNameIndicatesSecret
		}

		findings = append(findings, newFinding(
			file,
			path,
			"xml_element",
			"xml_text",
			elem,
			text,
			reason,
		))
	}

	return findings
}

// detectXMLAttrReasons flags attribute values whose shape betrays a secret
// (connection strings, JWTs, private keys, credential-bearing URLs) regardless
// of the attribute's name. This catches the common .NET case of a
// <connectionStrings> entry whose connectionString="...;User Id=...;Password=..."
// carries a credential even though its name attribute is benign.
//
// Attributes whose name already signals a secret are skipped here because the
// name-driven path in detectXMLAttrs runs the same classifySecretReason check
// and would otherwise produce a duplicate finding.
func detectXMLAttrReasons(file, path string, attrs []xml.Attr, rules []Rule) []Finding {
	var findings []Finding

	for _, attr := range attrs {
		if nameSignalsSecretForAny(attr.Name.Local, rules) {
			continue
		}

		value := normalizeScalar(attr.Value)
		if value == "" || valueSuppressed(value, rules) {
			continue
		}

		reason := classifySecretReason(value)
		if reason == "" {
			continue
		}

		findings = append(findings, newFinding(
			file,
			path,
			"xml_attr",
			"xml_attr_value",
			attr.Name.Local,
			value,
			reason,
		))
	}

	return findings
}

// detectXMLTextReason flags element text whose shape betrays a secret
// (connection strings, JWTs, private keys, credential-bearing URLs) regardless
// of the element's name, e.g. <connectionString>...;User Id=...;Password=...</connectionString>.
//
// Elements whose name already signals a secret are skipped because the
// name-driven detectXMLElementText runs the same classifySecretReason check and
// would otherwise produce a duplicate finding.
func detectXMLTextReason(file, path, elem, text string, rules []Rule) []Finding {
	if nameSignalsSecretForAny(elem, rules) {
		return nil
	}

	value := normalizeScalar(text)
	if value == "" || valueSuppressed(value, rules) {
		return nil
	}

	reason := classifySecretReason(value)
	if reason == "" {
		return nil
	}

	return []Finding{newFinding(
		file,
		path,
		"xml_element",
		"xml_text",
		elem,
		value,
		reason,
	)}
}

// nameSignalsSecretForAny reports whether name signals a secret under any rule.
func nameSignalsSecretForAny(name string, rules []Rule) bool {
	for _, rule := range rules {
		if nameSignalsSecret(name, rule) {
			return true
		}
	}

	return false
}

func detectXMLAttrs(file, path string, attrs []xml.Attr, rules []Rule) []Finding {
	var findings []Finding
	lang := languageName(file)

	byName := make(map[string]string, len(attrs))
	for _, attr := range attrs {
		byName[attr.Name.Local] = attr.Value
	}

	for _, rule := range rules {
		// Attribute whose own name signals a secret (e.g. <db password="..."/>).
		for _, attr := range attrs {
			if !nameSignalsSecret(attr.Name.Local, rule) {
				continue
			}

			value := normalizeScalar(attr.Value)
			if shouldSkipValue(value, rule, lang) {
				continue
			}

			reason := classifySecretReason(value)
			if reason == "" && !isLikelySecretValue(attr.Name.Local, value, rule, lang) {
				continue
			}
			if reason == "" {
				reason = reasonNameIndicatesSecret
			}

			findings = append(findings, newFinding(
				file,
				path,
				"xml_attr",
				"xml_attr_value",
				attr.Name.Local,
				value,
				reason,
			))
		}

		// Name/value attribute pair (e.g. <add key="ApiKey" value="..."/>).
		for _, namePath := range rule.NamePaths {
			name, ok := byName[namePath]
			if !ok || !nameSignalsSecret(name, rule) {
				continue
			}

			for _, valuePath := range rule.ValuePaths {
				raw, ok := byName[valuePath]
				if !ok {
					continue
				}

				value := normalizeScalar(raw)
				if value == "" || shouldSkipValue(value, rule, lang) {
					continue
				}

				reason := classifySecretReason(value)
				if reason == "" && !isLikelySecretValue(name, value, rule, lang) {
					continue
				}
				if reason == "" {
					reason = reasonNameIndicatesSecret
				}

				findings = append(findings, newFinding(
					file,
					path,
					namePath,
					valuePath,
					name,
					value,
					reason,
				))
			}
		}
	}

	return findings
}
