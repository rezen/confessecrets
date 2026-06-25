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

// urlPartnerExpr matches a partner finding that names or carries a service /
// token-endpoint URL: its name's leaf segment (the part after the last dot, so a
// dotted path like "...arvato.url.token" with leaf "token" is not mistaken for a
// URL while "token_url" / "service.uri" still match) reads url/uri/endpoint, or
// its value was surfaced as a service-endpoint URL (an info: finding) or as a URL
// carrying credentials. Shared by every built-in rule that pairs a credential
// with the URL it authenticates against.
const urlPartnerExpr = `let leaf = lower(last(split(name, "."))); ` +
	`leaf contains "url" || leaf contains "uri" || ` +
	`leaf contains "endpoint" || reason startsWith "info:" || ` +
	`reason contains "url"`

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
		// An OAuth2 / OIDC client secret paired with the service or token-endpoint
		// URL it authenticates against. A partner counts as a URL when its name reads
		// like one (url/uri/endpoint) or its value was surfaced as a service-endpoint
		// URL (an info: finding) or as a URL carrying credentials. Listed after
		// oauth-client-credentials so a client_id pairing still wins when present
		// (first matching rule wins per primary); the URL is the fallback partner.
		ID:       "client-secret-url",
		Match:    FindingMatcher{NameRegex: `(?i)client[_-]?secret`},
		Partners: []FindingMatcher{{Expr: urlPartnerExpr}},
	},
	{
		// A JWT paired with the service or token-endpoint URL it is presented to or
		// issued by. A finding counts as a JWT when its value shape was detected as
		// one (reason jwt_indicator, or gitleaks:jwt for the pattern-matched form)
		// or its key name reads like one (a "jwt" key whose value the detector did
		// not classify — truncated, templated, or referenced indirectly). Same URL
		// partner test as client-secret-url.
		ID: "jwt-url",
		Match: FindingMatcher{Expr: `reason == "jwt_indicator" || ` +
			`reason == "gitleaks:jwt" || lower(name) contains "jwt"`},
		Partners: []FindingMatcher{{Expr: urlPartnerExpr}},
	},
	{
		// An OAuth2 / OIDC client_id paired with the service or token-endpoint URL
		// it authenticates against. A client_id consumed here as a primary is still
		// available to oauth-client-credentials as a client_secret's partner (it is
		// tagged, not removed, until folded), so the canonical secret pairing is
		// unaffected; this only adds context when no client_secret claims it.
		ID:       "client-id-url",
		Match:    FindingMatcher{NameRegex: `(?i)client[_-]?id`},
		Partners: []FindingMatcher{{Expr: urlPartnerExpr}},
	},
	{
		// A password paired with both the user it belongs to and the service URL it
		// authenticates against. Requires both partners, so it claims the primary
		// only when the full credential context is present; the password-user and
		// password-url fallbacks below cover the partial cases (first matching rule
		// wins per primary, so the richer pairing is tried first).
		ID:    "password-credentials",
		Match: FindingMatcher{NameRegex: `(?i)passw(?:or)?d|pwd`},
		Partners: []FindingMatcher{
			{NameRegex: `(?i)user`},
			{Expr: urlPartnerExpr},
		},
	},
	{
		// A password paired with just the user it belongs to (no URL nearby).
		ID:       "password-user",
		Match:    FindingMatcher{NameRegex: `(?i)passw(?:or)?d|pwd`},
		Partners: []FindingMatcher{{NameRegex: `(?i)user`}},
	},
	{
		// A password paired with just the service URL it authenticates against (no
		// user nearby).
		ID:       "password-url",
		Match:    FindingMatcher{NameRegex: `(?i)passw(?:or)?d|pwd`},
		Partners: []FindingMatcher{{Expr: urlPartnerExpr}},
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
	{
		// A cloud function/handler paired with the service URL it is exposed at
		// (e.g. an Azure Functions or AWS Lambda function next to its endpoint URL).
		// Names are lower-cased before the substring test so an upper-case
		// FUNCTION_KEY / BASE_URL pair still correlates.
		ID:   "function-url",
		When: `lower(name) contains "function" && lower(prev.name) contains "url"`,
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
				enrichMetaFromPartner(&findings[i], sec)
				// A correlated partner is always in the same file as its primary, so
				// drop the redundant file path from the embedded copy — only its
				// in-file location (Path) is kept.
				sec.File = ""
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

// enrichMetaFromPartner lifts the identity of a correlated partner into the
// primary's Meta: a client-id-like partner name fills ClientID, a client
// secret/key-like name fills ClientKey, a user-like name fills Username, and a
// URL-like partner (its name reads url/uri/endpoint, or its value was surfaced as
// a service-endpoint URL) fills URL. Only empty fields are filled, so
// value-derived metadata is never overwritten. The secret-ish ClientKey takes the
// partner's redacted Value; the non-secret ClientID/Username/URL take its raw value.
func enrichMetaFromPartner(primary *Finding, partner Finding) {
	name := strings.ToLower(partner.Name)
	// The URL classification keys off the leaf segment (after the last dot), matching
	// the client-secret-url partner matcher, so a dotted path like "...url.token"
	// (leaf "token") is not treated as a URL.
	leaf := name
	if idx := strings.LastIndexByte(name, '.'); idx >= 0 {
		leaf = name[idx+1:]
	}

	var dst *string
	var src string
	switch {
	case strings.Contains(name, "client") && (strings.Contains(name, "secret") || strings.Contains(name, "key")):
		dst, src = &primaryMeta(primary).ClientKey, partner.Value
	case strings.Contains(name, "client") && strings.Contains(name, "id"),
		strings.Contains(name, "appid"), strings.Contains(name, "app_id"):
		dst, src = &primaryMeta(primary).ClientID, partner.RawValue
	case strings.Contains(name, "user"):
		dst, src = &primaryMeta(primary).Username, partner.RawValue
	case strings.Contains(leaf, "url"), strings.Contains(leaf, "uri"),
		strings.Contains(leaf, "endpoint"),
		strings.HasPrefix(partner.Reason, "info:"), strings.Contains(partner.Reason, "url"):
		dst, src = &primaryMeta(primary).URL, partner.RawValue
	default:
		return
	}

	if *dst == "" {
		*dst = src
	}
}

// primaryMeta returns the finding's Meta, allocating it on first use so callers
// can populate identity fields without a nil check.
func primaryMeta(f *Finding) *Meta {
	if f.Meta == nil {
		f.Meta = &Meta{}
	}
	return f.Meta
}

// correlationEnv exposes the primary (current) and a candidate prior finding
// (prev) to a correlation expression. The primary's fields are available both at
// the top level (so `name` refers to the current finding, as in a filter
// expression) and under `current`; the candidate's fields are under `prev`. Each
// finding is projected with the same variable set a filter expression sees (see
// filterEnv). A zero pair gives the compiler the names and types for
// type-checking.
func correlationEnv(current, prev Finding) map[string]any {
	env := filterEnv(current)
	env["current"] = filterEnv(current)
	env["prev"] = filterEnv(prev)
	return env
}
