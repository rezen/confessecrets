package scanner

import (
	"regexp"

	"github.com/expr-lang/expr/vm"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Files     FilePolicy       `yaml:"files"`
	Rules     []RuleConfig     `yaml:"rules"`
	Detectors []DetectorConfig `yaml:"detectors"`
	// Filter is an optional list of filter rules. Each rule is an expr-lang
	// expression evaluated against every finding; what happens to a match depends
	// on the rule's action (drop it, or tag it). See FilterConfig and Filter for
	// the available variables. Empty means no filtering.
	Filter FilterConfigs `yaml:"filter"`
	// Correlations is an optional list of correlation rules. Each pairs a primary
	// finding with one or more partner findings seen just before it in the same
	// file; on a match the primary embeds the partners (which are dropped from the
	// top-level results) and all are tagged. See CorrelationConfig.
	Correlations []CorrelationConfig `yaml:"correlations"`
	// Info is an optional list of informational-finding rules. Each is an expr-lang
	// predicate over a value and its key name that, on a match, surfaces the value
	// as a levelInfo finding ("info:<id>") — a recognized non-credential identifier
	// such as a cloud account/tenant/subscription ID. They extend a built-in set
	// (see builtinInfoRules) and are evaluated before it. See InfoRuleConfig.
	Info []InfoRuleConfig `yaml:"info"`
	// Stopwords are extra non-secret words applied across all rules. As with the
	// built-in stopword set (gitleaks' DefaultStopWords), a name-driven candidate
	// is dropped when its value contains (case-insensitively) any of these as a
	// substring. They extend, never replace, the always-on built-in set. Use this
	// to silence project-specific placeholders such as "redacted".
	Stopwords []string `yaml:"stopwords"`
}

// Filter actions decide what happens to a finding a filter rule matches.
const (
	// filterActionFilter drops a matching finding (the default action).
	filterActionFilter = "filter"
	// filterActionTag keeps a matching finding and adds the rule's ID to its tags.
	filterActionTag = "tag"
)

// FilterConfig is one entry of the top-level filter list. It accepts two YAML
// forms: a bare scalar (the expression, with the default "filter" action) or a
// mapping with id/action/filter keys.
type FilterConfig struct {
	// ID labels the rule; it is the tag added to findings when Action is "tag".
	ID string `yaml:"id"`
	// Action is "filter" (drop matches, the default) or "tag" (keep and tag them).
	Action string `yaml:"action"`
	// Filter is the expr-lang expression evaluated against each finding.
	Filter string `yaml:"filter"`
}

// UnmarshalYAML accepts either a scalar expression (action defaults to "filter")
// or an {id, action, filter} mapping.
func (f *FilterConfig) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind == yaml.ScalarNode {
		f.Filter = value.Value
		f.Action = filterActionFilter
		return nil
	}

	var m struct {
		ID     string `yaml:"id"`
		Action string `yaml:"action"`
		Filter string `yaml:"filter"`
	}
	if err := value.Decode(&m); err != nil {
		return err
	}

	f.ID = m.ID
	f.Action = m.Action
	f.Filter = m.Filter
	if f.Action == "" {
		f.Action = filterActionFilter
	}
	return nil
}

// FilterConfigs is the top-level filter list. It accepts a YAML sequence of
// entries or, for convenience, a single bare entry (scalar or mapping) treated
// as a one-element list.
type FilterConfigs []FilterConfig

func (fs *FilterConfigs) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind == yaml.SequenceNode {
		var list []FilterConfig
		if err := value.Decode(&list); err != nil {
			return err
		}
		*fs = list
		return nil
	}

	var one FilterConfig
	if err := one.UnmarshalYAML(value); err != nil {
		return err
	}
	*fs = FilterConfigs{one}
	return nil
}

type FilePolicy struct {
	Allow []string `yaml:"allow"`
	Deny  []string `yaml:"deny"`
}

type RuleConfig struct {
	NamePaths  []string `yaml:"name_paths"`
	ValuePaths []string `yaml:"value_paths"`
	// NameRegexes is a list of name patterns. Each entry is either a bare regex
	// string or a {name, regex} mapping; a name matching any entry signals a
	// secret.
	NameRegexes []NameRegexEntry `yaml:"name_regexes"`
	MinValueLen int              `yaml:"min_value_len"`
	// MinEntropy, when > 0, gates name-driven findings: a value flagged because
	// its key name looks secret-y must have at least this Shannon entropy
	// (bits/symbol) or it is treated as a placeholder and dropped. Values that
	// carry a definite secret reason (JWT, private key, URL credentials) bypass
	// the gate.
	MinEntropy float64 `yaml:"min_entropy"`
	// HighEntropyThreshold, when > 0, enables a generic detector that flags any
	// value whose Shannon entropy meets the threshold, regardless of key name.
	HighEntropyThreshold float64 `yaml:"high_entropy_threshold"`
	// MaxNameValueSimilarity, when > 0, drops name-driven findings whose value is
	// at least this similar (0..1) to the key name — near-echoes such as
	// password="password1" or passwd="passw0rd" that the exact-echo check misses.
	// Similarity is the max of normalized Levenshtein and Jaro-Winkler.
	MaxNameValueSimilarity float64  `yaml:"max_name_value_similarity"`
	IgnoreNamePatterns     []string `yaml:"ignore_name_patterns"`
	IgnoreValuePrefixes    []string `yaml:"ignore_value_prefixes"`
	IgnoreValuePatterns    []string `yaml:"ignore_value_patterns"`
}

// NameRegexEntry is one entry of a rule's name_regexes list. It accepts two YAML
// forms: a bare scalar (the regex, unnamed) or a mapping with `name` and `regex`
// keys. The name is an optional human-readable label for the pattern.
type NameRegexEntry struct {
	Name  string
	Regex string
}

// UnmarshalYAML accepts either a scalar regex string or a {name, regex} mapping.
func (e *NameRegexEntry) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind == yaml.ScalarNode {
		e.Regex = value.Value
		return nil
	}

	var m struct {
		Name  string `yaml:"name"`
		Regex string `yaml:"regex"`
	}
	if err := value.Decode(&m); err != nil {
		return err
	}

	e.Name = m.Name
	e.Regex = m.Regex
	return nil
}

type Rule struct {
	NamePaths              []string
	ValuePaths             []string
	NameRegexes            []NamedRegex
	MinValueLen            int
	MinEntropy             float64
	HighEntropyThreshold   float64
	MaxNameValueSimilarity float64
	IgnoreNamePatterns     []*regexp.Regexp
	IgnoreValuePrefixes    []string
	IgnoreValuePatterns    []*regexp.Regexp
	// Stopwords are the effective extra non-secret words (lowercased) checked by
	// substring containment on top of the built-in stopword set. They come from
	// the global Config.Stopwords and are copied onto every rule at compile time
	// (see CompileConfig). Nil when none are configured.
	Stopwords []string
}

// NamedRegex is a compiled name pattern with its optional label.
type NamedRegex struct {
	Name  string
	Regex *regexp.Regexp
}

// DetectorConfig is a trufflehog-style custom value-pattern detector as parsed
// from YAML, recognizing a secret by the shape of the value alone. The schema
// mirrors trufflehog's custom detectors
// (https://trufflesecurity.com/docs/custom-detectors): a detector fires when a
// keyword is present and every named regex matches. Live HTTP `verify`
// endpoints are intentionally unsupported — confessecrets is an offline scanner
// that redacts values rather than exfiltrating them — so that field is ignored.
type DetectorConfig struct {
	// Name labels the detector and appears in findings as "custom:<name>".
	Name string `yaml:"name"`
	// Keywords gate the detector: at least one must be present (case-insensitive)
	// in the value or its key name before the regexes are evaluated. An empty
	// list means the detector always runs its regexes.
	Keywords []string `yaml:"keywords"`
	// Regex maps a name to a pattern; every pattern must match the value for the
	// detector to fire. A pattern's first capture group, when present, is the
	// reported secret, otherwise the whole match is.
	Regex map[string]string `yaml:"regex"`
	// PrimaryRegexName selects which regex supplies the reported/entropy-checked
	// value; it defaults to the alphabetically first regex when omitted.
	PrimaryRegexName string `yaml:"primary_regex_name"`
	// ExcludeRegexesMatch drops a match whose primary value matches any of these.
	ExcludeRegexesMatch []string `yaml:"exclude_regexes_match"`
	// ExcludeWords drops a candidate when any of these appears (case-insensitive)
	// in the value or its key name.
	ExcludeWords []string `yaml:"exclude_words"`
	// Entropy, when > 0, drops matches whose primary value has Shannon entropy
	// (bits per symbol) below the threshold.
	Entropy float64 `yaml:"entropy"`
}

// CustomDetector is a compiled DetectorConfig, ready to match against values.
// Regexes is kept sorted by name so iteration and primary selection stay
// deterministic despite Go's randomized map ordering.
type CustomDetector struct {
	Name           string
	Keywords       []string // lowercased
	Regexes        []NamedRegex
	Primary        *regexp.Regexp // one of Regexes' patterns; supplies the reported value
	ExcludeRegexes []*regexp.Regexp
	ExcludeWords   []string // lowercased
	MinEntropy     float64
}

// InfoRuleConfig is one informational-finding rule as parsed from YAML. A rule
// fires when its expr-lang Match predicate (evaluated over the value and its key
// name) is true, surfacing the value as a levelInfo finding reasoned
// "info:<id>". It accepts two YAML forms: a mapping with id/match keys, or a bare
// scalar treated as the match expression (the id then defaults to the expression
// itself). See InfoRule for the variables and helpers a Match can reference.
type InfoRuleConfig struct {
	// ID labels the rule and appears in findings as "info:<id>".
	ID string `yaml:"id"`
	// Match is the expr-lang predicate; a true result yields the info finding.
	Match string `yaml:"match"`
}

// UnmarshalYAML accepts either a scalar match expression (id defaults to the
// expression) or an {id, match} mapping.
func (c *InfoRuleConfig) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind == yaml.ScalarNode {
		c.Match = value.Value
		c.ID = value.Value
		return nil
	}

	var m struct {
		ID    string `yaml:"id"`
		Match string `yaml:"match"`
	}
	if err := value.Decode(&m); err != nil {
		return err
	}

	c.ID = m.ID
	c.Match = m.Match
	if c.ID == "" {
		c.ID = m.Match
	}
	return nil
}

// CorrelationConfig defines a relationship between findings: a primary finding
// (matched by Match, or the When expression's `current`) is enriched when every
// partner is present among the recent prior findings of the same file. It accepts
// two forms — structured (Match + Partners) or an expr-lang expression (When,
// with `current` and the `prev` finding-list in scope). On a match the partners
// are embedded into the primary, dropped from the top-level results, and all are
// tagged with Tag (defaulting to ID).
type CorrelationConfig struct {
	ID       string           `yaml:"id"`
	Match    FindingMatcher   `yaml:"match"`
	Partners []FindingMatcher `yaml:"partners"`
	When     string           `yaml:"when"`
	Tag      string           `yaml:"tag"`
}

// FindingMatcher matches a single finding. It has two mutually exclusive forms:
// the regex form matches by one or more finding fields (all set fields must match,
// AND); the expression form (Expr) is an expr-lang predicate evaluated against the
// finding's fields (the same variables a filter expression sees, e.g. `name`,
// `reason`, `entropy`). An empty matcher matches nothing.
type FindingMatcher struct {
	NameRegex   string `yaml:"name_regex"`
	ReasonRegex string `yaml:"reason_regex"`
	PathRegex   string `yaml:"path_regex"`
	Expr        string `yaml:"expr"`
}

// Correlation is a compiled CorrelationConfig. Exactly one form is active:
// structured (match + partners) or expression (program != nil).
type Correlation struct {
	ID       string
	Tag      string
	match    findingMatcher
	partners []findingMatcher
	program  *vm.Program
}

// findingMatcher is a compiled FindingMatcher. Either program is set (expression
// form) or some of the regex fields are (regex form); nil regex fields are
// unconstrained.
type findingMatcher struct {
	name    *regexp.Regexp
	reason  *regexp.Regexp
	path    *regexp.Regexp
	program *vm.Program
}

// RuleSet is the compiled detection configuration applied to a file: the
// name-driven Rules, the value-shape Detectors (custom, trufflehog-style), the
// post-detection Filters, and the cross-finding Correlations. They travel
// together so every file is scanned under one effective config, including
// repo-local overrides.
type RuleSet struct {
	Rules        []Rule
	Detectors    []CustomDetector
	Filters      []*Filter
	Correlations []Correlation
	// InfoRules recognize non-credential identifiers (cloud account/tenant/
	// subscription IDs) and surface them as levelInfo findings. See InfoRule.
	InfoRules []InfoRule
}

// prevWindow is how many recent findings are carried as correlation context: the
// minPrevWindow floor, grown to fit the rule with the most partners so any
// defined correlation can always be satisfied within the window.
func (s RuleSet) prevWindow() int {
	n := minPrevWindow
	for _, c := range s.Correlations {
		if len(c.partners) > n {
			n = len(c.partners)
		}
	}
	return n
}

type Finding struct {
	// File is the path to the source file. Top-level findings always set it; it is
	// cleared (and so omitted) on findings embedded under Correlated, since a
	// correlated partner is always in the same file as its primary — only its
	// in-file location (Path) is meaningful there.
	File string `json:"file,omitempty"`
	// Path is the in-document location: a structured locator such as "$.db.password"
	// for parsed config, or an INI "[section] line:N". A bare "line:N" is omitted as
	// redundant, since File and Line already carry that location.
	Path string `json:"path,omitempty"`
	// Line is the 1-based source line the finding sits on, derived from Path for
	// the line-oriented formats (dotenv, properties, ini, and the line-based JSON/
	// YAML fallbacks). It is 0 (and omitted) for structured paths like "$.a.b" that
	// carry no line number.
	Line int `json:"line,omitempty"`
	// Lang is the source language or config format of the file the finding came
	// from (e.g. "python", "json"). Omitted for unsupported file types.
	Lang string `json:"lang,omitempty"`
	// Level is the severity of the finding: "high" for a detected secret (the
	// default) or "info" for an informational match such as a recognized service
	// URL that is worth surfacing but is not itself a credential.
	Level               string  `json:"level,omitempty"`
	NamePath            string  `json:"name_path"`
	ValuePath           string  `json:"value_path"`
	Name                string  `json:"name"`
	Value               string  `json:"value"`
	RawValue            string  `json:"raw_value"`
	ValueSHA256         string  `json:"value_sha256"`
	Entropy             float64 `json:"entropy"`
	NameValueSimilarity float64 `json:"name_value_similarity"`
	Reason              string  `json:"reason"`
	// Tags are free-form labels attached to the finding: the ID of any "tag"-action
	// filter rule the finding matched, and any correlation tag. The source language
	// or config format is carried in the dedicated Lang field rather than a tag.
	// Omitted when empty.
	Tags []string `json:"tags,omitempty"`
	// Filtered is set when the finding matched the config filter but was retained
	// (via -show-filtered) instead of dropped; FilteredReason holds the expression
	// that excluded it. Both are omitted from normal, unfiltered findings.
	Filtered       bool   `json:"filtered,omitempty"`
	FilteredReason string `json:"filtered_reason,omitempty"`
	Meta           *Meta  `json:"meta,omitempty"`
	// Correlated holds secondary findings folded into this primary by a
	// correlation rule (e.g. the client_id paired with this client_secret).
	// Embedded secondaries are removed from the top-level results and surface only
	// nested here.
	Correlated []Finding `json:"correlated,omitempty"`
}

// JWT holds claims and the header decoded from a JSON Web Token value. The
// standard iss/iat/exp claims map to dedicated fields; the decoded header
// (alg/typ/kid, ...) lives in Header and every other claim in Extra. All fields
// are optional and omitted from output when absent.
type JWT struct {
	Issuer     string                 `json:"issuer,omitempty"`
	Iat        int64                  `json:"iat,omitempty"`
	Expiration int64                  `json:"expiration,omitempty"`
	IsExpired  bool                   `json:"is_expired,omitempty"`
	Header     map[string]interface{} `json:"header,omitempty"`
	Extra      map[string]interface{} `json:"extra,omitempty"`
}

// Meta holds optional, value-derived metadata attached to a finding. JWT is
// populated from JSON Web Token values; the identity fields (Username, Host,
// URL, ClientID, ClientKey) are derived from URL credentials, connection-string
// values, and correlated partner findings. All fields are optional and omitted
// from output when absent.
type Meta struct {
	JWT       *JWT                   `json:"jwt,omitempty"`
	Username  string                 `json:"username,omitempty"`
	AppId     string                 `json:"app_id,omitempty"`
	Host      string                 `json:"host,omitempty"`
	URL       string                 `json:"url,omitempty"`
	ClientID  string                 `json:"client_id,omitempty"`
	ClientKey string                 `json:"client_key,omitempty"`
	Extra     map[string]interface{} `json:"extra,omitempty"`
}
