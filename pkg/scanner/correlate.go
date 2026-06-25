package scanner

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/expr-lang/expr"
)

// secondaryTag labels a finding that was folded into a primary as a correlation
// partner, alongside the rule's own tag.
const secondaryTag = "secondary"

// builtinCorrelations are high-confidence credential pairings shipped by default,
// applied to every scan after any user-configured correlations (so user rules win
// the first-match-per-primary race). They are deliberately conservative — keyed on
// the canonical names of paired credentials — to avoid folding unrelated findings.
var builtinCorrelations = []CorrelationConfig{
	{
		// AWS access key id (caught by its value shape) + the secret access key
		// (caught by its name) that signs requests with it.
		ID:       "aws-credential-pair",
		Match:    FindingMatcher{NameRegex: `(?i)secret[_-]?access[_-]?key`},
		Partners: []FindingMatcher{{ReasonRegex: `^gitleaks:aws-access-token$`}},
	},
	{
		// OAuth2 / OIDC client credentials.
		ID:       "oauth-client-credentials",
		Match:    FindingMatcher{NameRegex: `(?i)client[_-]?secret`},
		Partners: []FindingMatcher{{NameRegex: `(?i)client[_-]?id`}},
	},
	{
		// OAuth1 consumer credentials.
		ID:       "consumer-credentials",
		Match:    FindingMatcher{NameRegex: `(?i)consumer[_-]?secret`},
		Partners: []FindingMatcher{{NameRegex: `(?i)consumer[_-]?key`}},
	},
	{
		// Generic api key + api secret pairing.
		ID:       "api-key-secret",
		Match:    FindingMatcher{NameRegex: `(?i)api[_-]?secret`},
		Partners: []FindingMatcher{{NameRegex: `(?i)api[_-]?key`}},
	},
}

// CompileCorrelations turns parsed correlation configs into ready-to-use rules,
// compiling their matchers or expression. A rule with a non-empty `when` is the
// expression form; otherwise it is structured and must list at least one partner.
// The applied tag defaults to the rule id. The built-in correlations are appended
// after the user-configured ones, so a user rule takes precedence when both could
// claim the same primary (first match per primary wins).
func CompileCorrelations(cfgs []CorrelationConfig) ([]Correlation, error) {
	var out []Correlation

	all := make([]CorrelationConfig, 0, len(cfgs)+len(builtinCorrelations))
	all = append(all, cfgs...)
	all = append(all, builtinCorrelations...)

	for _, c := range all {
		label := c.ID
		if label == "" {
			label = c.When
		}

		tag := c.Tag
		if tag == "" {
			tag = c.ID
		}
		if strings.TrimSpace(tag) == "" {
			return nil, fmt.Errorf("correlation %q: requires an id or tag", label)
		}

		if strings.TrimSpace(c.When) != "" {
			program, err := expr.Compile(c.When, expr.Env(correlationEnv(Finding{}, Finding{})), expr.AsBool())
			if err != nil {
				return nil, fmt.Errorf("correlation %q: %w", label, err)
			}
			out = append(out, Correlation{ID: c.ID, Tag: tag, program: program})
			continue
		}

		match, err := compileFindingMatcher(c.Match)
		if err != nil {
			return nil, fmt.Errorf("correlation %q match: %w", label, err)
		}
		if len(c.Partners) == 0 {
			return nil, fmt.Errorf("correlation %q: requires partners or a when expression", label)
		}

		partners := make([]findingMatcher, 0, len(c.Partners))
		for i, pc := range c.Partners {
			pm, err := compileFindingMatcher(pc)
			if err != nil {
				return nil, fmt.Errorf("correlation %q partner %d: %w", label, i, err)
			}
			partners = append(partners, pm)
		}

		out = append(out, Correlation{ID: c.ID, Tag: tag, match: match, partners: partners})
	}

	return out, nil
}

// compileFindingMatcher compiles a FindingMatcher into either its expression or
// its regex form; the two are mutually exclusive. An all-empty matcher is rejected
// so it cannot silently match every finding.
func compileFindingMatcher(c FindingMatcher) (findingMatcher, error) {
	hasRegex := c.NameRegex != "" || c.ReasonRegex != "" || c.PathRegex != ""

	if strings.TrimSpace(c.Expr) != "" {
		if hasRegex {
			return findingMatcher{}, fmt.Errorf("matcher cannot combine expr with regex fields")
		}
		program, err := expr.Compile(c.Expr, expr.Env(filterEnv(Finding{})), expr.AsBool())
		if err != nil {
			return findingMatcher{}, err
		}
		return findingMatcher{program: program}, nil
	}

	if !hasRegex {
		return findingMatcher{}, fmt.Errorf("matcher has no patterns")
	}

	var m findingMatcher
	var err error
	compile := func(pattern string) (*regexp.Regexp, error) {
		if pattern == "" {
			return nil, nil
		}
		return regexp.Compile(pattern)
	}

	if m.name, err = compile(c.NameRegex); err != nil {
		return findingMatcher{}, err
	}
	if m.reason, err = compile(c.ReasonRegex); err != nil {
		return findingMatcher{}, err
	}
	if m.path, err = compile(c.PathRegex); err != nil {
		return findingMatcher{}, err
	}

	return m, nil
}

// matches reports whether f satisfies the matcher. The expression form runs its
// predicate against f's fields; the regex form requires every set pattern to match
// (AND). A matcher with neither form matches nothing.
func (m findingMatcher) matches(f Finding) bool {
	if m.program != nil {
		out, err := expr.Run(m.program, filterEnv(f))
		if err != nil {
			return false
		}
		ok, _ := out.(bool)
		return ok
	}

	if m.name == nil && m.reason == nil && m.path == nil {
		return false
	}
	if m.name != nil && !m.name.MatchString(f.Name) {
		return false
	}
	if m.reason != nil && !m.reason.MatchString(f.Reason) {
		return false
	}
	if m.path != nil && !m.path.MatchString(f.Path) {
		return false
	}
	return true
}

// correlateFindings folds correlated findings together: when a finding (the
// primary) satisfies a rule and every partner is found among the preceding
// findings within the look-back window, each partner is tagged, embedded into the
// primary's Correlated list, and removed from the returned top-level results. The
// primary is tagged too. Findings are processed in order, the first matching rule
// wins per primary, and a finding already consumed as a partner is neither a
// primary nor reused as another partner. Order is otherwise preserved.
func correlateFindings(findings []Finding, rules []Correlation) []Finding {
	if len(rules) == 0 || len(findings) == 0 {
		return findings
	}

	window := minPrevWindow
	for _, r := range rules {
		if len(r.partners) > window {
			window = len(r.partners)
		}
	}

	consumed := make([]bool, len(findings))
	for i := range findings {
		if consumed[i] {
			continue
		}

		for _, rule := range rules {
			secondaries, ok := rule.partnersFor(findings, i, window, consumed)
			if !ok {
				continue
			}

			findings[i].Tags = appendTag(findings[i].Tags, rule.Tag)
			for _, j := range secondaries {
				consumed[j] = true
				sec := findings[j]
				sec.Tags = appendTag(sec.Tags, rule.Tag)
				sec.Tags = appendTag(sec.Tags, secondaryTag)
				findings[i].Correlated = append(findings[i].Correlated, sec)
			}
			break // first matching rule wins
		}
	}

	kept := findings[:0]
	for i, f := range findings {
		if !consumed[i] {
			kept = append(kept, f)
		}
	}
	return kept
}

// partnersFor returns the indices of the findings that satisfy rule for the
// primary at index i, searching the up-to-window findings before it. For the
// structured form every partner matcher must claim a distinct, not-yet-consumed
// prior finding (greedy assignment). For the expression form every prior finding
// in the window for which the predicate holds (current=primary, prev=candidate)
// becomes a partner; ok is true when at least one is found.
func (r Correlation) partnersFor(findings []Finding, i, window int, consumed []bool) ([]int, bool) {
	start := i - window
	if start < 0 {
		start = 0
	}

	if r.program != nil {
		var matched []int
		for j := start; j < i; j++ {
			if consumed[j] {
				continue
			}
			out, err := expr.Run(r.program, correlationEnv(findings[i], findings[j]))
			if err != nil {
				continue
			}
			if ok, _ := out.(bool); ok {
				matched = append(matched, j)
			}
		}
		return matched, len(matched) > 0
	}

	if !r.match.matches(findings[i]) {
		return nil, false
	}

	used := make(map[int]bool, len(r.partners))
	assigned := make([]int, 0, len(r.partners))
	for _, pm := range r.partners {
		found := -1
		for j := start; j < i; j++ {
			if consumed[j] || used[j] {
				continue
			}
			if pm.matches(findings[j]) {
				found = j
				break
			}
		}
		if found == -1 {
			return nil, false
		}
		used[found] = true
		assigned = append(assigned, found)
	}

	return assigned, true
}

// correlationEnv exposes the primary (current) and a candidate prior finding
// (prev) to a correlation expression, each as the same variable set a filter
// expression sees (see filterEnv). A zero pair gives the compiler the names and
// types for type-checking.
func correlationEnv(current, prev Finding) map[string]any {
	return map[string]any{
		"current": filterEnv(current),
		"prev":    filterEnv(prev),
	}
}
