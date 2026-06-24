package scanner

import (
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"
)

// CompileDetectors turns parsed custom-detector configs into ready-to-use
// CustomDetectors, compiling their regular expressions, resolving the primary
// regex, and lowercasing keyword/exclude-word lists for case-insensitive
// matching. It mirrors CompileRules and fails on the first invalid pattern.
func CompileDetectors(configs []DetectorConfig) ([]CustomDetector, error) {
	var detectors []CustomDetector

	for _, dc := range configs {
		if strings.TrimSpace(dc.Name) == "" {
			return nil, fmt.Errorf("custom detector: name is required")
		}

		if len(dc.Regex) == 0 {
			return nil, fmt.Errorf("custom detector %q: at least one regex is required", dc.Name)
		}

		// Compile the named regexes in a stable (alphabetical) order so the
		// default primary regex and "all must match" iteration are deterministic
		// despite Go's randomized map ordering.
		names := make([]string, 0, len(dc.Regex))
		for name := range dc.Regex {
			names = append(names, name)
		}
		sort.Strings(names)

		regexes := make([]NamedRegex, 0, len(names))
		for _, name := range names {
			re, err := regexp.Compile(dc.Regex[name])
			if err != nil {
				return nil, fmt.Errorf("custom detector %q: regex %q: %w", dc.Name, name, err)
			}
			regexes = append(regexes, NamedRegex{Name: name, Regex: re})
		}

		// The primary regex supplies the value reported and entropy/exclude-checked.
		// It defaults to the first (alphabetically) regex unless named explicitly.
		primary := regexes[0].Regex
		if dc.PrimaryRegexName != "" {
			found := false
			for _, nr := range regexes {
				if nr.Name == dc.PrimaryRegexName {
					primary = nr.Regex
					found = true
					break
				}
			}
			if !found {
				return nil, fmt.Errorf("custom detector %q: primary_regex_name %q is not one of the configured regexes", dc.Name, dc.PrimaryRegexName)
			}
		}

		var excludeRegexes []*regexp.Regexp
		for _, pattern := range dc.ExcludeRegexesMatch {
			re, err := regexp.Compile(pattern)
			if err != nil {
				return nil, fmt.Errorf("custom detector %q: exclude_regexes_match %q: %w", dc.Name, pattern, err)
			}
			excludeRegexes = append(excludeRegexes, re)
		}

		detectors = append(detectors, CustomDetector{
			Name:           dc.Name,
			Keywords:       lowerAll(dc.Keywords),
			Regexes:        regexes,
			Primary:        primary,
			ExcludeRegexes: excludeRegexes,
			ExcludeWords:   lowerAll(dc.ExcludeWords),
			MinEntropy:     dc.Entropy,
		})
	}

	return detectors, nil
}

// match reports whether the detector fires on value (the key it came from is
// passed as name to give keyword/exclude-word checks the same context a
// trufflehog chunk would have) and returns the matched primary secret.
//
// The trufflehog semantics applied, in order: at least one keyword must be
// present; no exclude word may be present; every named regex must match; the
// primary match must not hit any exclude_regexes_match; and the primary match's
// Shannon entropy must meet the configured minimum.
func (d CustomDetector) match(value, name string) (string, bool) {
	hay := strings.ToLower(value + " " + name)

	if len(d.Keywords) > 0 && !containsAny(hay, d.Keywords) {
		return "", false
	}

	if containsAny(hay, d.ExcludeWords) {
		return "", false
	}

	primaryMatch := ""
	for _, nr := range d.Regexes {
		m := nr.Regex.FindStringSubmatch(value)
		if m == nil {
			return "", false
		}
		if nr.Regex == d.Primary {
			primaryMatch = matchResult(m)
		}
	}

	if primaryMatch == "" {
		return "", false
	}

	for _, re := range d.ExcludeRegexes {
		if re.MatchString(primaryMatch) {
			return "", false
		}
	}

	if d.MinEntropy > 0 && shannonEntropy(primaryMatch) < d.MinEntropy {
		return "", false
	}

	return primaryMatch, true
}

// matchResult returns the secret a regex extracted: its first capture group when
// one is defined and populated, otherwise the whole match. This mirrors
// trufflehog, where a capture group narrows the result to the token itself.
func matchResult(m []string) string {
	if len(m) > 1 && m[1] != "" {
		return m[1]
	}

	return m[0]
}

// valueEntropy returns the Shannon entropy of a finding's value, normalized the
// same way the entropy gate and high-entropy detector measure it and rounded to
// two decimals for stable, readable output.
func valueEntropy(value string) float64 {
	return round2(shannonEntropy(normalizeScalar(value)))
}

// round2 rounds f to two decimals for stable, readable output.
func round2(f float64) float64 {
	return math.Round(f*100) / 100
}

// nameValueSimilarity scores how closely a value resembles its key name, in
// [0,1] where 1 is identical. It is the max of two case-insensitive measures over
// the lowercased name and unquoted value: normalized Levenshtein (1 - edits/len)
// and Jaro-Winkler. Taking the max means either signal alone can mark a near-echo
// placeholder; Jaro-Winkler earns its place because the inputs are short and the
// fakes are prefix-weighted mutations (secret/secrets, passwd/passw0rd).
func nameValueSimilarity(name, value string) float64 {
	a := strings.ToLower(name)
	b := strings.ToLower(normalizeScalar(value))

	return math.Max(normalizedLevenshtein(a, b), jaroWinkler(a, b))
}

// normalizedLevenshtein converts the edit distance between a and b into a
// similarity in [0,1]: 1 for identical strings, 0 for wholly different ones of
// equal length. Two empty strings are defined as identical.
func normalizedLevenshtein(a, b string) float64 {
	maxLen := len([]rune(a))
	if l := len([]rune(b)); l > maxLen {
		maxLen = l
	}
	if maxLen == 0 {
		return 1
	}

	return 1 - float64(levenshtein(a, b))/float64(maxLen)
}

// jaroWinkler returns the Jaro-Winkler similarity of a and b in [0,1], boosting
// the base Jaro score for strings that share a common prefix (up to four runes) —
// the pattern of placeholder mutations like passwd/passw0rd.
func jaroWinkler(a, b string) float64 {
	j := jaro(a, b)

	ra, rb := []rune(a), []rune(b)
	prefix := 0
	for prefix < len(ra) && prefix < len(rb) && prefix < 4 && ra[prefix] == rb[prefix] {
		prefix++
	}

	const p = 0.1 // standard prefix scaling factor
	return j + float64(prefix)*p*(1-j)
}

// jaro returns the Jaro similarity of a and b in [0,1].
func jaro(a, b string) float64 {
	ra, rb := []rune(a), []rune(b)
	la, lb := len(ra), len(rb)

	if la == 0 && lb == 0 {
		return 1
	}
	if la == 0 || lb == 0 {
		return 0
	}

	// Two runes may match only within this window of each other's position.
	window := max(la, lb)/2 - 1
	if window < 0 {
		window = 0
	}

	aMatched := make([]bool, la)
	bMatched := make([]bool, lb)
	matches := 0

	for i := 0; i < la; i++ {
		start := i - window
		if start < 0 {
			start = 0
		}
		end := i + window + 1
		if end > lb {
			end = lb
		}
		for k := start; k < end; k++ {
			if bMatched[k] || ra[i] != rb[k] {
				continue
			}
			aMatched[i] = true
			bMatched[k] = true
			matches++
			break
		}
	}

	if matches == 0 {
		return 0
	}

	// Count transpositions: matched runes that appear out of order.
	transpositions := 0
	k := 0
	for i := 0; i < la; i++ {
		if !aMatched[i] {
			continue
		}
		for !bMatched[k] {
			k++
		}
		if ra[i] != rb[k] {
			transpositions++
		}
		k++
	}
	t := float64(transpositions) / 2

	m := float64(matches)
	return (m/float64(la) + m/float64(lb) + (m-t)/m) / 3
}

// shannonEntropy returns the Shannon entropy (in bits per symbol) of s over its
// runes, used to gate detectors whose configured `entropy` rejects low-variety
// matches such as placeholders and repeated characters.
func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}

	counts := map[rune]float64{}
	total := 0.0
	for _, r := range s {
		counts[r]++
		total++
	}

	entropy := 0.0
	for _, c := range counts {
		p := c / total
		entropy -= p * math.Log2(p)
	}

	return entropy
}

func containsAny(haystack string, needles []string) bool {
	for _, n := range needles {
		if n != "" && strings.Contains(haystack, n) {
			return true
		}
	}

	return false
}

func lowerAll(values []string) []string {
	if len(values) == 0 {
		return nil
	}

	out := make([]string, len(values))
	for i, v := range values {
		out[i] = strings.ToLower(v)
	}

	return out
}
