package scanner

import (
	"regexp"

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

// RuleSet is the compiled detection configuration applied to a file: the
// name-driven Rules and the value-shape Detectors (custom, trufflehog-style).
// The two travel together so every file is scanned under one effective config,
// including repo-local overrides.
type RuleSet struct {
	Rules     []Rule
	Detectors []CustomDetector
	Filters   []*Filter
}

type Finding struct {
	File                string  `json:"file"`
	Path                string  `json:"path"`
	NamePath            string  `json:"name_path"`
	ValuePath           string  `json:"value_path"`
	Name                string  `json:"name"`
	Value               string  `json:"value"`
	RawValue            string  `json:"raw_value"`
	ValueSHA256         string  `json:"value_sha256"`
	Entropy             float64 `json:"entropy"`
	NameValueSimilarity float64 `json:"name_value_similarity"`
	Reason              string  `json:"reason"`
	// Tags are free-form labels attached to the finding: a "lang:<name>" tag for
	// the source language or config format, plus the ID of any "tag"-action filter
	// rule the finding matched. Omitted when empty.
	Tags []string `json:"tags,omitempty"`
	// Filtered is set when the finding matched the config filter but was retained
	// (via -show-filtered) instead of dropped; FilteredReason holds the expression
	// that excluded it. Both are omitted from normal, unfiltered findings.
	Filtered       bool   `json:"filtered,omitempty"`
	FilteredReason string `json:"filtered_reason,omitempty"`
	Meta           *Meta  `json:"meta,omitempty"`
}

// Meta holds optional, value-derived metadata. It is currently populated from
// JWT claims when the finding's value is a JSON Web Token; all fields are
// optional and omitted from output when absent.
type Meta struct {
	Issuer     string                 `json:"issuer,omitempty"`
	Iat        int64                  `json:"iat,omitempty"`
	Expiration int64                  `json:"expiration,omitempty"`
	IsExpired  bool                   `json:"is_expired,omitempty"`
	Extra      map[string]interface{} `json:"extra,omitempty"`
}
