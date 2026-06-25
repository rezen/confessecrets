package scanner

import (
	"fmt"
	"strings"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"
)

// InfoRule is a compiled informational-finding rule: an expr-lang
// (https://expr-lang.org) predicate over a value and its key name that, when it
// matches, yields a levelInfo finding reasoned "info:<id>". Info rules recognize
// non-credential identifiers worth surfacing for inventory — cloud account,
// tenant, and subscription IDs — without raising them to the severity of a
// secret. They are data-driven so new identifiers can be added via config rather
// than code (see builtinInfoRules for the shipped set and Config.Info to extend).
//
// The variables and helpers available to an expression are:
//
//	name   (string)          the key name (e.g. "subscription_id")
//	value  (string)          the raw scalar value
//	words  (func) -> []string the key split into lowercase identifier words, so
//	                         camelCase/snake_case/kebab-case all compare equally:
//	                         words("subscriptionId") == ["subscription", "id"].
//
// expr-lang built-ins (matches, contains, in, lower, startsWith, ...) are
// available, so a rule reads e.g.
//
//	"subscription" in words(name) && value matches "(?i)^[0-9a-f-]{36}$"
type InfoRule struct {
	ID      string
	program *vm.Program
	source  string
}

// guidValueExpr is the value test for a GUID/UUID in canonical 8-4-4-4-12 hex
// form, anchored to the whole value. Shared by the Azure subscription/tenant
// rules, whose identifiers are both GUIDs.
const guidValueExpr = `value matches "(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"`

// builtinInfoRules are the informational identifier rules shipped by default,
// evaluated after any user-configured rules so a user rule wins the
// first-match-per-value race. Each is name-gated: the value shape alone (a GUID,
// 12 digits, a 6-6-6 group) is too common to flag without the key naming the
// provider/identifier, so bare values elsewhere stay quiet.
var builtinInfoRules = []InfoRuleConfig{
	// Azure subscription ID — a GUID under a subscription_id key.
	{ID: "azure-subscription-id", Match: `"subscription" in words(name) && "id" in words(name) && ` + guidValueExpr},
	// Azure tenant ID — a GUID under a tenant_id key.
	{ID: "azure-tenant-id", Match: `"tenant" in words(name) && "id" in words(name) && ` + guidValueExpr},
	// AWS account ID — 12 digits under a key naming both "aws" and "account"
	// (aws_account_id, awsAccountId, ...); a generic account_id does not qualify.
	{ID: "aws-account-id", Match: `"aws" in words(name) && "account" in words(name) && value matches "^[0-9]{12}$"`},
	// GCP billing account ID — XXXXXX-XXXXXX-XXXXXX (three 6-char hex groups)
	// under a key naming both "gcp" and "account".
	{ID: "gcp-billing-account-id", Match: `"gcp" in words(name) && "account" in words(name) && value matches "(?i)^[0-9A-F]{6}-[0-9A-F]{6}-[0-9A-F]{6}$"`},
}

// compileInfoRules turns parsed info-rule configs into ready-to-use rules,
// type-checking each expression against the available variables and requiring a
// boolean result so configuration errors fail fast. User-configured rules are
// evaluated before the built-ins, so a user rule takes precedence when both could
// claim the same value (first match wins). Entries with an empty expression are
// skipped; every rule must carry an id (the "info:<id>" reason it applies).
func compileInfoRules(cfgs []InfoRuleConfig) ([]InfoRule, error) {
	all := make([]InfoRuleConfig, 0, len(cfgs)+len(builtinInfoRules))
	all = append(all, cfgs...)
	all = append(all, builtinInfoRules...)

	var out []InfoRule
	for _, c := range all {
		if strings.TrimSpace(c.Match) == "" {
			continue
		}
		if strings.TrimSpace(c.ID) == "" {
			return nil, fmt.Errorf("info rule %q: requires an id", c.Match)
		}

		program, err := expr.Compile(c.Match, expr.Env(infoEnv("", "")), expr.AsBool())
		if err != nil {
			return nil, fmt.Errorf("info rule %q: %w", c.ID, err)
		}

		out = append(out, InfoRule{ID: c.ID, program: program, source: c.Match})
	}

	return out, nil
}

// matchInfoRule returns the id of the first info rule whose predicate matches the
// given name/value, or "" if none match.
func matchInfoRule(name, value string, rules []InfoRule) string {
	for _, r := range rules {
		out, err := expr.Run(r.program, infoEnv(name, value))
		if err != nil {
			// expr.AsBool type-checks at compile time, so a runtime error here is
			// unexpected; skip the rule rather than fail the whole scan.
			continue
		}
		if matched, _ := out.(bool); matched {
			return r.ID
		}
	}

	return ""
}

// infoEnv exposes the variables and helpers an info-rule expression can
// reference. Passing zero strings gives the compiler the variable names and types
// for type-checking. The `words` helper is identifierWords, which splits a key on
// separators and camelCase boundaries so casing/style never matters.
func infoEnv(name, value string) map[string]any {
	return map[string]any{
		"name":  name,
		"value": value,
		"words": identifierWords,
	}
}
