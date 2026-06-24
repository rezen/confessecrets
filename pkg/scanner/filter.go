package scanner

import (
	"fmt"
	"strings"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"
)

// Filter is a compiled expr-lang (https://expr-lang.org) expression that excludes
// findings: a finding is dropped when the expression evaluates to true against its
// fields. It lets a config suppress whole classes of false positives by their
// computed properties, e.g. `entropy <= 4 && name_value_similarity > 0.65` to drop
// low-entropy near-echoes.
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
	program *vm.Program
	source  string
}

// compileFilter compiles a filter expression, type-checking it against the finding
// fields and requiring a boolean result, so configuration errors fail fast. An
// empty (or whitespace-only) expression yields a nil Filter, meaning no filtering.
func compileFilter(source string) (*Filter, error) {
	if strings.TrimSpace(source) == "" {
		return nil, nil
	}

	program, err := expr.Compile(source, expr.Env(filterEnv(Finding{})), expr.AsBool())
	if err != nil {
		return nil, fmt.Errorf("filter %q: %w", source, err)
	}

	return &Filter{program: program, source: source}, nil
}

// Excludes reports whether finding matches the filter and should be dropped. A nil
// Filter excludes nothing.
func (f *Filter) Excludes(finding Finding) (bool, error) {
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

// applyFilter handles the findings excluded by filter, preserving order. By
// default an excluded finding is dropped; when includeFiltered is set it is kept
// instead, marked Filtered with the matching expression in FilteredReason. It
// returns findings unchanged when filter is nil.
func applyFilter(findings []Finding, filter *Filter, includeFiltered bool) ([]Finding, error) {
	if filter == nil || len(findings) == 0 {
		return findings, nil
	}

	kept := findings[:0]
	for _, finding := range findings {
		drop, err := filter.Excludes(finding)
		if err != nil {
			return nil, err
		}

		if drop {
			if !includeFiltered {
				continue
			}
			finding.Filtered = true
			finding.FilteredReason = filter.source
		}

		kept = append(kept, finding)
	}

	return kept, nil
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
