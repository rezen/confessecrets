package scanner

import "regexp"

type Config struct {
	Files FilePolicy   `yaml:"files"`
	Rules []RuleConfig `yaml:"rules"`
}

type FilePolicy struct {
	Allow []string `yaml:"allow"`
	Deny  []string `yaml:"deny"`
}

type RuleConfig struct {
	NamePaths           []string `yaml:"name_paths"`
	ValuePaths          []string `yaml:"value_paths"`
	NameRegex           string   `yaml:"name_regex"`
	MinValueLen         int      `yaml:"min_value_len"`
	IgnoreNamePatterns  []string `yaml:"ignore_name_patterns"`
	IgnoreValuePrefixes []string `yaml:"ignore_value_prefixes"`
	IgnoreValuePatterns []string `yaml:"ignore_value_patterns"`
}

type Rule struct {
	NamePaths           []string
	ValuePaths          []string
	NameRegex           *regexp.Regexp
	MinValueLen         int
	IgnoreNamePatterns  []*regexp.Regexp
	IgnoreValuePrefixes []string
	IgnoreValuePatterns []*regexp.Regexp
}

type Finding struct {
	File        string `json:"file"`
	Path        string `json:"path"`
	NamePath    string `json:"name_path"`
	ValuePath   string `json:"value_path"`
	Name        string `json:"name"`
	Value       string `json:"value"`
	RawValue    string `json:"raw_value"`
	ValueSHA256 string `json:"value_sha256"`
	Reason      string `json:"reason"`
	Meta        *Meta  `json:"meta,omitempty"`
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
