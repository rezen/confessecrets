package scanner

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/tailscale/hujson"
	"github.com/tidwall/jsonc"
	"gopkg.in/yaml.v3"
)

// LoadConfig reads and parses the scanner configuration from path.
func LoadConfig(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}

	data = stripBOM(data)

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, err
	}

	return cfg, nil
}

// CompileRules turns parsed rule configs into ready-to-use Rules, compiling
// their regular expressions and applying defaults.
func CompileRules(configs []RuleConfig) ([]Rule, error) {
	var rules []Rule

	for _, rc := range configs {
		nameRegexes, err := compileNameRegexes(rc)
		if err != nil {
			return nil, err
		}

		var ignorePatterns []*regexp.Regexp
		for _, pattern := range rc.IgnoreValuePatterns {
			re, err := regexp.Compile(pattern)
			if err != nil {
				return nil, err
			}
			ignorePatterns = append(ignorePatterns, re)
		}

		var ignoreNamePatterns []*regexp.Regexp
		for _, pattern := range rc.IgnoreNamePatterns {
			re, err := regexp.Compile(pattern)
			if err != nil {
				return nil, err
			}
			ignoreNamePatterns = append(ignoreNamePatterns, re)
		}

		if rc.MinValueLen == 0 {
			rc.MinValueLen = 8
		}

		rules = append(rules, Rule{
			NamePaths:              rc.NamePaths,
			ValuePaths:             rc.ValuePaths,
			NameRegexes:            nameRegexes,
			MinValueLen:            rc.MinValueLen,
			MinEntropy:             rc.MinEntropy,
			HighEntropyThreshold:   rc.HighEntropyThreshold,
			MaxNameValueSimilarity: rc.MaxNameValueSimilarity,
			IgnoreNamePatterns:     ignoreNamePatterns,
			IgnoreValuePrefixes:    rc.IgnoreValuePrefixes,
			IgnoreValuePatterns:    ignorePatterns,
		})
	}

	return rules, nil
}

// compileNameRegexes compiles a rule's name_regexes patterns, preserving order.
func compileNameRegexes(rc RuleConfig) ([]NamedRegex, error) {
	var compiled []NamedRegex
	for _, e := range rc.NameRegexes {
		re, err := regexp.Compile(e.Regex)
		if err != nil {
			return nil, err
		}
		compiled = append(compiled, NamedRegex{Name: e.Name, Regex: re})
	}

	return compiled, nil
}

// CompileConfig compiles a parsed Config into the RuleSet used to scan a file,
// pairing its name-driven rules with its value-shape custom detectors. It is the
// single entry point for turning loaded config (base or repo-local) into a
// ready-to-use RuleSet.
func CompileConfig(cfg Config) (RuleSet, error) {
	rules, err := CompileRules(cfg.Rules)
	if err != nil {
		return RuleSet{}, err
	}

	detectors, err := CompileDetectors(cfg.Detectors)
	if err != nil {
		return RuleSet{}, err
	}

	filters, err := compileFilters(cfg.Filter)
	if err != nil {
		return RuleSet{}, err
	}

	correlations, err := CompileCorrelations(cfg.Correlations)
	if err != nil {
		return RuleSet{}, err
	}

	return RuleSet{Rules: rules, Detectors: detectors, Filters: filters, Correlations: correlations}, nil
}

// Walk invokes fn for root if it is a file, or for every file beneath it if it
// is a directory.
func Walk(root string, fn func(string) error) error {
	info, err := os.Stat(root)
	if err != nil {
		return err
	}

	if !info.IsDir() {
		return fn(root)
	}

	return filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		return fn(path)
	})
}

// ShouldScan reports whether path passes the configured allow/deny policy.
func ShouldScan(path string, policy FilePolicy) bool {
	path = filepath.ToSlash(path)

	for _, pattern := range policy.Deny {
		if globMatch(pattern, path) {
			return false
		}
	}

	if len(policy.Allow) == 0 {
		return true
	}

	for _, pattern := range policy.Allow {
		if globMatch(pattern, path) {
			return true
		}
	}

	return false
}

func globMatch(pattern, path string) bool {
	pattern = filepath.ToSlash(pattern)
	ok, err := doublestar.Match(pattern, path)
	return err == nil && ok
}

// ScanOptions tunes how ScanFile post-processes findings.
type ScanOptions struct {
	// IncludeFiltered keeps findings excluded by the config filter in the results,
	// marking each Filtered with its FilteredReason, instead of dropping them.
	IncludeFiltered bool
}

// ScanFile reads path, selects a Detector for its format, and returns any
// findings. Unsupported file types yield no findings and no error.
func ScanFile(path string, set RuleSet, opts ScanOptions) ([]Finding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	data = stripBOM(data)

	detector := detectorFor(path)
	if detector == nil {
		return nil, nil
	}

	findings := detector.Detect(path, data, set)
	findings = correlateFindings(findings, set.Correlations)
	if tag := languageTag(path); tag != "" {
		for i := range findings {
			findings[i].Tags = appendTag(findings[i].Tags, tag)
		}
	}

	return applyFilters(findings, set.Filters, opts.IncludeFiltered)
}

// languageTag returns the "lang:<name>" tag for path's file type — the source
// language for code files (e.g. "lang:python") or the format for structured
// config (e.g. "lang:json") — or "" for unsupported types.
func languageTag(path string) string {
	if isEnvFile(path) {
		return "lang:dotenv"
	}

	if spec := sourceLangForExt(strings.ToLower(filepath.Ext(path))); spec != nil {
		return "lang:" + spec.name
	}

	switch strings.ToLower(filepath.Ext(path)) {
	case ".json", ".jsonc":
		return "lang:json"
	case ".yaml", ".yml":
		return "lang:yaml"
	case ".xml", ".config":
		return "lang:xml"
	case ".properties":
		return "lang:properties"
	case ".ini":
		return "lang:ini"
	}

	return ""
}

// isEnvFile reports whether path is a dotenv-style file: ".env", a variant such
// as ".env.local"/".env.production", or any file ending in ".env"
// (e.g. "app.env"). These are matched by base name because filepath.Ext is
// unreliable here (Ext(".env.local") is ".local", Ext(".env") is ".env").
func isEnvFile(path string) bool {
	base := strings.ToLower(filepath.Base(path))

	return base == ".env" ||
		strings.HasPrefix(base, ".env.") ||
		strings.HasSuffix(base, ".env")
}

func parseFlexibleJSON(data []byte, out *any) error {
	data = stripBOM(data)

	if err := json.Unmarshal(data, out); err == nil {
		return nil
	}

	if clean, err := standardizeJSON(data); err == nil {
		if err := json.Unmarshal(clean, out); err == nil {
			return nil
		}
	}

	clean := jsonc.ToJSON(data)
	if err := json.Unmarshal(clean, out); err == nil {
		return nil
	}

	clean = relaxedJSONCleanup(data)
	return json.Unmarshal(clean, out)
}

func standardizeJSON(data []byte) ([]byte, error) {
	ast, err := hujson.Parse(data)
	if err != nil {
		return nil, err
	}

	ast.Standardize()
	return ast.Pack(), nil
}

func relaxedJSONCleanup(data []byte) []byte {
	s := strings.TrimSpace(string(data))

	s = strings.TrimPrefix(s, "module.exports =")
	s = strings.TrimPrefix(s, "export default")
	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(s, ";")

	return []byte(s)
}

func stripBOM(data []byte) []byte {
	return bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF})
}
