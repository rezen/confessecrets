package scanner

//go:generate go run ../../cmd/generate/patterns -in ../../gitleaks.toml -out patterns_gitleaks_gen.go

import (
	"regexp"
	"strings"
)

// ValuePattern is a gitleaks-style rule that recognizes a secret by the shape of
// the value itself, independent of any surrounding key name.
type ValuePattern struct {
	ID    string
	Regex *regexp.Regexp
	// Allow are per-rule allowlist regexes (carried from gitleaks.toml): when the
	// Regex matches but any Allow regex also matches the value, it is suppressed
	// (e.g. AWS example keys ending in EXAMPLE). Nil for the hand-curated rules.
	Allow []*regexp.Regexp
}

// gitleaksPatterns are high-confidence, self-identifying secret token patterns
// adapted from gitleaks (github.com/gitleaks/gitleaks, cmd/generate/config/rules).
//
// They are adjusted for Go's RE2 engine and for matching values that have
// already been extracted from their keys: the raw-text leading/trailing context
// and capture groups used in the upstream rules are dropped, keeping the core
// token shape. Keyword-gated rules that rely on surrounding prose (e.g. heroku,
// telegram) are intentionally omitted because they would match bare UUIDs here.
var gitleaksPatterns = []ValuePattern{
	{ID: "aws-access-token", Regex: regexp.MustCompile(`\b(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16}\b`)},
	{ID: "github-pat", Regex: regexp.MustCompile(`\bghp_[0-9a-zA-Z]{36}\b`)},
	{ID: "github-fine-grained-pat", Regex: regexp.MustCompile(`\bgithub_pat_\w{82}\b`)},
	{ID: "github-oauth", Regex: regexp.MustCompile(`\bgho_[0-9a-zA-Z]{36}\b`)},
	{ID: "github-app-token", Regex: regexp.MustCompile(`\b(?:ghu|ghs)_[0-9a-zA-Z]{36}\b`)},
	{ID: "gitlab-pat", Regex: regexp.MustCompile(`\bglpat-[\w-]{20}\b`)},
	{ID: "slack-bot-token", Regex: regexp.MustCompile(`xoxb-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*`)},
	{ID: "slack-user-token", Regex: regexp.MustCompile(`xox[pe](?:-[0-9]{10,13}){3}-[a-zA-Z0-9-]{28,34}`)},
	{ID: "stripe-access-token", Regex: regexp.MustCompile(`\b(?:sk|rk)_(?:test|live|prod)_[a-zA-Z0-9]{10,99}\b`)},
	{ID: "sendgrid-api-token", Regex: regexp.MustCompile(`\bSG\.[A-Za-z0-9=_.\-]{66}`)},
	{ID: "twilio-api-key", Regex: regexp.MustCompile(`\bSK[0-9a-fA-F]{32}\b`)},
	{ID: "npm-access-token", Regex: regexp.MustCompile(`\bnpm_[a-zA-Z0-9]{36}\b`)},
	{ID: "pypi-upload-token", Regex: regexp.MustCompile(`pypi-AgEIcHlwaS5vcmc[\w-]{50,1000}`)},
	{ID: "openai-api-key", Regex: regexp.MustCompile(`\b(?:sk-(?:proj|svcacct|admin)-(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58})T3BlbkFJ(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58})|sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20})\b`)},
	{ID: "anthropic-api-key", Regex: regexp.MustCompile(`\bsk-ant-api03-[a-zA-Z0-9_\-]{93}AA\b`)},
	{ID: "gcp-api-key", Regex: regexp.MustCompile(`\bAIza[\w-]{35}\b`)},
	{ID: "jwt", Regex: regexp.MustCompile(`\bey[a-zA-Z0-9]{17,}\.ey[a-zA-Z0-9/\\_-]{17,}\.(?:[a-zA-Z0-9/\\_-]{10,}={0,2})?`)},
	{ID: "private-key", Regex: regexp.MustCompile(`(?i)-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----[\s\S-]{64,}?KEY(?: BLOCK)?-----`)},
	{ID: "square-access-token", Regex: regexp.MustCompile(`\b(?:EAAA|sq0atp-)[\w-]{22,60}\b`)},
	{ID: "shopify-shared-secret", Regex: regexp.MustCompile(`\bshpss_[a-fA-F0-9]{32}\b`)},
}

// matchValuePattern returns the ID of the first gitleaks pattern whose regex
// matches value, or "" if none match. The hand-curated patterns are consulted
// first so their tuned forms take precedence over the auto-generated set.
func matchValuePattern(value string) string {
	if id := scanValuePatterns(value, gitleaksPatterns); id != "" {
		return id
	}
	return scanValuePatterns(value, gitleaksGeneratedPatterns)
}

// scanValuePatterns returns the ID of the first pattern in pats whose regex
// matches value and whose allowlist (if any) does not, or "" if none match.
func scanValuePatterns(value string, pats []ValuePattern) string {
	for _, p := range pats {
		if p.Regex.MatchString(value) && !allowlisted(value, p.Allow) {
			return p.ID
		}
	}

	return ""
}

// allowlisted reports whether value matches any of a pattern's allowlist regexes
// (i.e. is a known false positive such as a vendor example key).
func allowlisted(value string, allow []*regexp.Regexp) bool {
	for _, a := range allow {
		if a.MatchString(value) {
			return true
		}
	}

	return false
}

// infoURLPatterns recognize service endpoint URLs that are worth surfacing for
// inventory and review but are not themselves credentials. A match yields an
// informational (levelInfo) finding rather than a secret, reasoned "info:<id>".
var infoURLPatterns = []ValuePattern{
	// ---- AWS ----
	// Lambda function URLs, e.g. abc123.lambda-url.us-east-1.on.aws
	{ID: "aws-lambda-url", Regex: regexp.MustCompile(`(?i)\b[a-z0-9]+\.lambda-url\.[a-z0-9-]+\.on\.aws\b`)},
	// API Gateway (REST/HTTP), e.g. a1b2c3d4.execute-api.us-east-1.amazonaws.com
	{ID: "aws-api-gateway", Regex: regexp.MustCompile(`(?i)\b[a-z0-9]+\.execute-api\.[a-z0-9-]+\.amazonaws\.com\b`)},
	// AppSync GraphQL, e.g. abc.appsync-api.us-east-1.amazonaws.com
	{ID: "aws-appsync", Regex: regexp.MustCompile(`(?i)\b[a-z0-9]+\.appsync-api\.[a-z0-9-]+\.amazonaws\.com\b`)},

	// ---- Azure ----
	// App Service / Functions. Covers classic (app.azurewebsites.net),
	// SCM/Kudu (app.scm.azurewebsites.net), and the newer region-scoped
	// unique default hostnames (app-<hash>.<region>.azurewebsites.net and
	// app-<hash>.scm.<region>.azurewebsites.net).
	{ID: "azure-app-service", Regex: regexp.MustCompile(`(?i)\b[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.scm)?(?:\.[a-z0-9]+)?\.azurewebsites\.net\b`)},
	// API Management, e.g. myapi.azure-api.net
	{ID: "azure-api-management", Regex: regexp.MustCompile(`(?i)\b[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.azure-api\.net\b`)},
	// Container Apps, e.g. app.kindhill-a1b2c3.eastus.azurecontainerapps.io
	{ID: "azure-container-apps", Regex: regexp.MustCompile(`(?i)\b[a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+){2}\.azurecontainerapps\.io\b`)},
	// Static Web Apps, e.g. app.<random>.<region>.azurestaticapps.net
	{ID: "azure-static-web-apps", Regex: regexp.MustCompile(`(?i)\b[a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+)*\.azurestaticapps\.net\b`)},

	// ---- GCP ----
	// Cloud Functions (1st gen), e.g. us-central1-my-project.cloudfunctions.net
	{ID: "gcp-cloud-functions", Regex: regexp.MustCompile(`(?i)\b[a-z][a-z0-9-]*\.cloudfunctions\.net\b`)},
	// Cloud Run / Cloud Functions v2. Covers deterministic
	// (service-<projectnumber>.<region>.run.app), non-deterministic
	// (service-<hash>.run.app), and legacy (service-<hash>-<code>.a.run.app).
	{ID: "gcp-cloud-run", Regex: regexp.MustCompile(`(?i)\b[a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+)?\.(?:a\.)?run\.app\b`)},

	// ---- Vercel ----
	// Production and per-deployment URLs, e.g. project.vercel.app and
	// project-<hash>-<scope>.vercel.app
	{ID: "vercel", Regex: regexp.MustCompile(`(?i)\b[a-z0-9][a-z0-9-]*\.vercel\.app\b`)},

	// ---- Heroku ----
	// App hostname, e.g. myapp.herokuapp.com
	{ID: "heroku-app", Regex: regexp.MustCompile(`(?i)\b[a-z0-9][a-z0-9-]*\.herokuapp\.com\b`)},
	// Current DNS/CNAME target, e.g. myapp.herokudns.com
	{ID: "heroku-dns", Regex: regexp.MustCompile(`(?i)\b[a-z0-9][a-z0-9-]*\.herokudns\.com\b`)},

	// ---- Other common FaaS / edge ----
	// Cloudflare Workers, e.g. name.subdomain.workers.dev
	{ID: "cloudflare-workers", Regex: regexp.MustCompile(`(?i)\b[a-z0-9][a-z0-9-]*\.[a-z0-9][a-z0-9-]*\.workers\.dev\b`)},
	// Netlify, e.g. site.netlify.app (functions at /.netlify/functions/<name>)
	{ID: "netlify", Regex: regexp.MustCompile(`(?i)\b[a-z0-9][a-z0-9-]*\.netlify\.app\b`)},
	// Supabase Edge Functions. Host alone (*.supabase.co) is broad, so this
	// anchors on the function path to stay function-specific.
	{ID: "supabase-functions", Regex: regexp.MustCompile(`(?i)\b[a-z0-9]+\.supabase\.co/functions/v1/[a-z0-9_-]+`)},
	// DigitalOcean Functions, e.g. faas-nyc1-abc123.doserverless.co
	{ID: "digitalocean-functions", Regex: regexp.MustCompile(`(?i)\bfaas-[a-z0-9]+-[a-z0-9]+\.doserverless\.co\b`)},

	// Fly.io, e.g. empty-sea-2541.fly.dev
	{ID: "fly-io", Regex: regexp.MustCompile(`(?i)\b[a-z0-9][a-z0-9-]*\.fly\.dev\b`)},
	// Render, e.g. my-service.onrender.com
	{ID: "render", Regex: regexp.MustCompile(`(?i)\b[a-z0-9][a-z0-9-]*\.onrender\.com\b`)},
	// Railway. Newer service domains use .up.railway.app; older use .railway.app
	{ID: "railway", Regex: regexp.MustCompile(`(?i)\b[a-z0-9][a-z0-9-]*\.(?:up\.)?railway\.app\b`)},
	// Koyeb, e.g. my-app-org.koyeb.app
	{ID: "koyeb", Regex: regexp.MustCompile(`(?i)\b[a-z0-9][a-z0-9-]*\.koyeb\.app\b`)},
	// AWS Amplify hosting, e.g. main.d1a2b3c4.amplifyapp.com
	{ID: "aws-amplify", Regex: regexp.MustCompile(`(?i)\b[a-z0-9][a-z0-9-]*\.amplifyapp\.com\b`)},

	// ---- Edge / isolate runtimes ----
	// Deno Deploy, e.g. my-project.deno.dev (and <project>-<id>.deno.dev)
	{ID: "deno-deploy", Regex: regexp.MustCompile(`(?i)\b[a-z0-9][a-z0-9-]*\.deno\.dev\b`)},
	// Cloudflare Pages, e.g. my-site.pages.dev
	{ID: "cloudflare-pages", Regex: regexp.MustCompile(`(?i)\b[a-z0-9][a-z0-9-]*\.pages\.dev\b`)},
	// Fastly Compute, e.g. my-service.edgecompute.app
	{ID: "fastly-compute", Regex: regexp.MustCompile(`(?i)\b[a-z0-9][a-z0-9-]*\.edgecompute\.app\b`)},
	// Fermyon Cloud (Spin/WASM), e.g. my-app.fermyon.app
	{ID: "fermyon-cloud", Regex: regexp.MustCompile(`(?i)\b[a-z0-9][a-z0-9-]*\.fermyon\.app\b`)},
	// Modal web endpoints, e.g. workspace--app-fn.modal.run
	{ID: "modal", Regex: regexp.MustCompile(`(?i)\b[a-z0-9][a-z0-9-]*\.modal\.run\b`)},
	// Val Town, e.g. user-valname.web.val.run
	{ID: "val-town", Regex: regexp.MustCompile(`(?i)\b(?:[a-z0-9][a-z0-9-]*\.)+val\.run\b`)},

	// ---- BaaS function/HTTP endpoints ----
	// Firebase Hosting / functions rewrites, e.g. my-app.web.app or *.firebaseapp.com
	{ID: "firebase-hosting", Regex: regexp.MustCompile(`(?i)\b[a-z0-9][a-z0-9-]*\.(?:web\.app|firebaseapp\.com)\b`)},
	// Convex HTTP actions (.convex.site) and API (.convex.cloud)
	{ID: "convex", Regex: regexp.MustCompile(`(?i)\b[a-z0-9][a-z0-9-]*\.convex\.(?:site|cloud)\b`)},
	// Twilio Functions, e.g. service-1234.twil.io
	{ID: "twilio-functions", Regex: regexp.MustCompile(`(?i)\b[a-z0-9][a-z0-9-]*\.twil\.io\b`)},

	// ---- AWS edge functions (run on AWS-owned infra, see notes) ----
	// CloudFront distribution domains often front CloudFront Functions / Lambda@Edge
	{ID: "aws-cloudfront", Regex: regexp.MustCompile(`(?i)\b[a-z0-9]+\.cloudfront\.net\b`)},

	// ---- Regional / enterprise clouds (BEST-EFFORT — verify vs real samples) ----
	// Scaleway Functions, e.g. <ns>-<fn>.functions.fnc.fr-par.scw.cloud
	{ID: "scaleway-functions", Regex: regexp.MustCompile(`(?i)\b[a-z0-9][a-z0-9-]*\.functions\.fnc\.[a-z0-9-]+\.scw\.cloud\b`)},
	// IBM Cloud Code Engine, e.g. app.abcd1234.us-south.codeengine.appdomain.cloud
	{ID: "ibm-code-engine", Regex: regexp.MustCompile(`(?i)\b[a-z0-9][a-z0-9-]*\.[a-z0-9]+\.[a-z0-9-]+\.codeengine\.appdomain\.cloud\b`)},
	// Alibaba Function Compute, e.g. <account-id>.<region>.fc.aliyuncs.com
	{ID: "alibaba-fc", Regex: regexp.MustCompile(`(?i)\b[0-9]+\.[a-z0-9-]+\.fc\.aliyuncs\.com\b`)},
	// Oracle Functions via OCI API Gateway, e.g. <id>.apigateway.<region>.oci.customer-oci.com
	{ID: "oracle-apigateway", Regex: regexp.MustCompile(`(?i)\b[a-z0-9]+\.apigateway\.[a-z0-9-]+\.oci\.customer-oci\.com\b`)},
	// Tencent SCF via API Gateway, e.g. service-xxxx-1250000000.<region>.apigw.tencentcs.com
	{ID: "tencent-scf", Regex: regexp.MustCompile(`(?i)\bservice-[a-z0-9]+-[0-9]+\.[a-z0-9-]+\.apigw\.tencentcs\.com\b`)},
}

// matchInfoURL returns the ID of the first info URL pattern whose regex matches
// value, or "" if none match.
func matchInfoURL(value string) string {
	for _, p := range infoURLPatterns {
		if p.Regex.MatchString(value) {
			return p.ID
		}
	}

	return ""
}

// ExaminationFocus bundles the single item under inspection for value-pattern
// detection: where it lives (File/Path), how it is labelled (Name), its scalar
// Value, and a snapshot of the most-recent prior findings for this file, kept
// for correlation context.
type ExaminationFocus struct {
	File         string
	Path         string
	Name         string
	Value        string
	PrevFindings []Finding
}

// minPrevWindow is the floor for how many recent findings are carried as
// correlation context; the effective window grows to fit the largest correlation
// rule (see RuleSet.prevWindow).
const minPrevWindow = 3

// recentFindings returns the up-to-n most recent findings, in append order, used
// to seed an ExaminationFocus.PrevFindings without carrying the whole slice.
func recentFindings(findings []Finding, n int) []Finding {
	if n <= 0 || len(findings) <= n {
		return findings
	}
	return findings[len(findings)-n:]
}

// detectValuePatterns scans a single value against the built-in gitleaks
// patterns and any configured custom (trufflehog-style) detectors, independent
// of the key name. It honors the configured value-ignore prefixes/patterns (so
// suppressions still apply) and emits at most one finding. The built-in patterns
// take precedence and are tagged "gitleaks:<rule-id>"; a custom detector match
// is tagged "custom:<detector-name>".
func detectValuePatterns(focus ExaminationFocus, set RuleSet) []Finding {
	value := normalizeScalar(focus.Value)
	if value == "" {
		return nil
	}

	if valueSuppressed(value, set.Rules) {
		return nil
	}

	// Recognized non-credential identifiers (cloud account/tenant/subscription IDs)
	// are surfaced at info level. These name-gated rules are data-driven and run
	// first so a GUID/12-digit/billing-ID value is never mistaken for a
	// high-entropy secret. See InfoRule and builtinInfoRules.
	if id := matchInfoRule(focus.Name, value, set.InfoRules); id != "" {
		return []Finding{infoFinding(focus, value, id)}
	}

	if id := matchValuePattern(value); id != "" {
		return []Finding{newFinding(
			focus.File,
			focus.Path,
			"value_pattern",
			"value_pattern",
			focus.Name,
			value,
			gitleaksReason(id),
		)}
	}

	for _, d := range set.Detectors {
		if _, ok := d.match(value, focus.Name); ok {
			return []Finding{newFinding(
				focus.File,
				focus.Path,
				"value_pattern",
				"value_pattern",
				focus.Name,
				value,
				customReason(d.Name),
			)}
		}
	}

	if reason := matchHighEntropy(value, set.Rules); reason != "" {
		return []Finding{newFinding(
			focus.File,
			focus.Path,
			"value_pattern",
			"value_pattern",
			focus.Name,
			value,
			reason,
		)}
	}

	// Service endpoint URLs are informational rather than secret: surface them at
	// info level so they don't carry the high severity of a credential.
	if id := matchInfoURL(value); id != "" {
		return []Finding{infoFinding(focus, value, id)}
	}

	return nil
}

// infoFinding builds a levelInfo finding for value with reason "info:<id>",
// marking a recognized non-credential match (a service URL or a cloud account /
// tenant / subscription identifier) rather than a secret.
func infoFinding(focus ExaminationFocus, value, id string) Finding {
	f := newFinding(
		focus.File,
		focus.Path,
		"value_pattern",
		"value_pattern",
		focus.Name,
		value,
		infoReason(id),
	)
	f.Level = levelInfo
	return f
}

// maxHighEntropyLen bounds the generic high-entropy detector to token-sized
// values. Real opaque secrets are short; long strings with many distinct symbols
// (source code, regexes, JSON blobs, prose) have naturally high per-symbol
// entropy and would otherwise be flagged wholesale.
const maxHighEntropyLen = 200

// matchHighEntropy reports a finding reason when value's Shannon entropy meets a
// rule's configured high_entropy_threshold, flagging opaque, high-randomness
// strings whose key name gives no hint they are secret. It restricts itself to
// single token-like values (no whitespace, bounded length, not natural language)
// so source code and prose don't trip the threshold, and embeds the measured
// entropy in the reason (e.g. "high_entropy:4.73"). The first rule with a
// threshold the value clears wins.
func matchHighEntropy(value string, rules []Rule) string {
	value = normalizeScalar(value)
	if value == "" {
		return ""
	}

	// A genuine opaque token is one whitespace-free run of bounded length; longer
	// or space-bearing values are code/prose whose entropy means nothing here.
	if len(value) > maxHighEntropyLen || strings.ContainsAny(value, " \t\r\n") {
		return ""
	}

	for _, rule := range rules {
		if rule.HighEntropyThreshold <= 0 {
			continue
		}
		if len(value) < rule.MinValueLen {
			continue
		}
		if looksLikeNaturalLanguage(value) {
			continue
		}

		if e := shannonEntropy(value); e >= rule.HighEntropyThreshold {
			return highEntropyReason(e)
		}
	}

	return ""
}

// valueSuppressed reports whether value is excluded by any rule's ignore
// prefixes or patterns. Unlike shouldSkipValue it does not treat plain URLs as
// skippable, since a tokenized secret can legitimately live inside a URL.
func valueSuppressed(value string, rules []Rule) bool {
	for _, rule := range rules {
		if shouldIgnoreValue(value, rule) {
			return true
		}
	}

	return false
}

// lastSegment returns the trailing key of a dotted JSON-ish path (e.g. the
// "password" of "$.db.password"), used as the finding name for raw values
// surfaced by value scanning.
func lastSegment(path string) string {
	if i := strings.LastIndex(path, "."); i >= 0 {
		return path[i+1:]
	}

	return path
}
