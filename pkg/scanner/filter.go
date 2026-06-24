package scanner

import (
	"fmt"
	"strings"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"
)

// Filter is a compiled filter rule: an expr-lang (https://expr-lang.org)
// predicate paired with the action to take on the findings it matches. A
// "filter"-action rule drops matches; a "tag"-action rule keeps them and adds its
// ID to their tags. It lets a config suppress (or label) whole classes of
// findings by their computed properties, e.g. `entropy <= 4 &&
// name_value_similarity > 0.65` to drop low-entropy near-echoes.
//
// The variables available to an expression are:
//
//	entropy               (number) Shannon entropy of the value, bits/symbol
//	name_value_similarity (number) name/value similarity, 0..1
//	value_length          (number) length of the raw value in bytes
//	name                  (string) the key name
//	value                 (string) the raw (unredacted) value
//	reason                (string) why the value was flagged
//	file, path, name_path, value_path (string) location fields
//
// expr-lang built-ins (matches, contains, startsWith, endsWith, lower, len, ...)
// are available, so richer rules like `value matches "(?i)example$"` work too.
type Filter struct {
	ID      string
	Action  string
	program *vm.Program
	source  string
}

// compileFilters compiles a list of filter rules, type-checking each expression
// against the finding fields and requiring a boolean result, so configuration
// errors fail fast. Entries with an empty expression are skipped; a tag-action
// rule must carry an id (the tag it applies). A nil/empty result means no
// filtering.
func compileFilters(cfgs []FilterConfig) ([]*Filter, error) {
	var filters []*Filter
	for _, c := range cfgs {
		if strings.TrimSpace(c.Filter) == "" {
			continue
		}

		action := c.Action
		if action == "" {
			action = filterActionFilter
		}
		switch action {
		case filterActionFilter:
		case filterActionTag:
			if strings.TrimSpace(c.ID) == "" {
				return nil, fmt.Errorf("filter %q: action %q requires an id", c.Filter, filterActionTag)
			}
		default:
			return nil, fmt.Errorf("filter %q: unknown action %q (want %q or %q)", c.Filter, action, filterActionFilter, filterActionTag)
		}

		program, err := expr.Compile(c.Filter, expr.Env(filterEnv(Finding{})), expr.AsBool())
		if err != nil {
			return nil, fmt.Errorf("filter %q: %w", c.Filter, err)
		}

		filters = append(filters, &Filter{ID: c.ID, Action: action, program: program, source: c.Filter})
	}

	return filters, nil
}

// Matches reports whether finding satisfies the filter's expression. A nil Filter
// matches nothing.
func (f *Filter) Matches(finding Finding) (bool, error) {
	if f == nil {
		return false, nil
	}

	out, err := expr.Run(f.program, filterEnv(finding))
	if err != nil {
		return false, fmt.Errorf("filter %q: %w", f.source, err)
	}

	// expr.AsBool guarantees a bool result at compile time.
	return out.(bool), nil
}

// applyFilters runs every filter rule against each finding, preserving order. A
// "tag"-action rule that matches adds its ID to the finding's tags; a
// "filter"-action rule that matches drops the finding (or, when includeFiltered
// is set, keeps it marked Filtered with the matching expression in
// FilteredReason). It returns findings unchanged when there are no filters.
func applyFilters(findings []Finding, filters []*Filter, includeFiltered bool) ([]Finding, error) {
	if len(filters) == 0 || len(findings) == 0 {
		return findings, nil
	}

	kept := findings[:0]
	for _, finding := range findings {
		drop := false
		dropReason := ""

		for _, f := range filters {
			matched, err := f.Matches(finding)
			if err != nil {
				return nil, err
			}
			if !matched {
				continue
			}

			if f.Action == filterActionTag {
				finding.Tags = appendTag(finding.Tags, f.ID)
				continue
			}

			// filterActionFilter: remember the first expression that dropped it.
			drop = true
			if dropReason == "" {
				dropReason = f.source
			}
		}

		if drop {
			if !includeFiltered {
				continue
			}
			finding.Filtered = true
			finding.FilteredReason = dropReason
		}

		kept = append(kept, finding)
	}

	return kept, nil
}

// appendTag adds tag to tags unless it is empty or already present, keeping tags
// free of blanks and duplicates.
func appendTag(tags []string, tag string) []string {
	if tag == "" {
		return tags
	}
	for _, t := range tags {
		if t == tag {
			return tags
		}
	}
	return append(tags, tag)
}

// filterEnv exposes a finding's fields as the variables a filter expression can
// reference. It is also used with a zero Finding to give the compiler the variable
// names and types for type-checking.
func filterEnv(f Finding) map[string]any {
	return map[string]any{
		"entropy":               f.Entropy,
		"name_value_similarity": f.NameValueSimilarity,
		"value_length":          len(f.RawValue),
		"name":                  f.Name,
		"value":                 f.RawValue,
		"reason":                f.Reason,
		"file":                  f.File,
		"path":                  f.Path,
		"name_path":             f.NamePath,
		"value_path":            f.ValuePath,
	}
}
