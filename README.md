# confessecrets

*Every config file has something to confess.*

A secret scanner for **structured configuration files** that gets your configs to
spill their guts. It walks a file or directory, hears out every confession, and
reports likely secrets as newline-delimited JSON (NDJSON).

It coaxes out secrets two complementary ways:

- **Name-driven** — a key whose name practically advertises guilt (e.g. `password`,
  `api_key`, `client_secret`) paired with a populated, secret-looking value.
- **Value-driven** — a value whose *shape* gives it away (gitleaks-style patterns
  such as `AKIA…`, `ghp_…`, `sk_live_…`), no matter how innocent its key name
  claims to be.

Supported formats: **JSON / JSONC**, **YAML**, **XML** (including .NET
`App.config` / `web.config` and other `.config` files), **dotenv**
(`.env`, `.env.*`, `*.env`), **Java properties** (`.properties`), and
**INI** (`.ini`).

It also scans **source code** — Python, JavaScript, TypeScript, Go, Java, C#,
Ruby, PHP, Kotlin, and Rust — with tree-sitter, so it can tell a hardcoded secret
from a runtime lookup.
`password = "hunter2"` confesses; `password = os.environ.get("SECRET")` does not,
because the value is a *call*, not a string literal. See
[Scanning source code](#scanning-source-code).

## Requirements

- Go **1.26+** (see `go.mod`)

## Build

```sh
# Build a binary into ./confessecrets
go build -o confessecrets ./cmd/confessecrets

# Or install it onto your PATH (into $GOBIN / $GOPATH/bin)
go install github.com/rezen/confessecrets/cmd/confessecrets@latest
```

### Releasing

Stamp the commit and build date into the binary via `-ldflags` so they show up
in `version.String()` (the `Number` const is bumped in the source — see
`pkg/version/version.go`):

```sh
go build -ldflags "\
  -X github.com/rezen/confessecrets/pkg/version.Commit=$(git rev-parse --short HEAD) \
  -X github.com/rezen/confessecrets/pkg/version.Date=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  -o confessecrets ./cmd/confessecrets
```

## Run

The scanner is the `cmd/confessecrets` package — run the **package**, not a single
file:

```sh
# From source
go run ./cmd/confessecrets -config config.yaml -path ./path/to/scan

# Or with the built binary
./confessecrets -config config.yaml -path ./path/to/scan
```

> Note: `go run main.go` will fail — the program is split across several files in
> the package. Use `go run ./cmd/confessecrets` (or `go run .` from inside that
> directory).

Findings are written as NDJSON to stdout by default. Redirect or `tee` to save:

```sh
go run ./cmd/confessecrets -path ~/repos | tee found.txt
```

### Flags

| Flag           | Default       | Description                                            |
|----------------|---------------|--------------------------------------------------------|
| `-config`      | `config.yaml` | Path to the scanner config                             |
| `-path`        | `.`           | File or directory to scan                              |
| `-output`      | `-`           | Output file, or `-` for stdout                         |
| `-repo-config` | `true`        | Respect repo-local config at repo roots (`=false` off) |
| `-scan`        | `all`         | What to scan: `all`, `source` (only source code), or `config` (only structured config, omit source code) |
| `-show-filtered` | `false`     | Keep findings excluded by the [filter](#custom-filter), marked `filtered: true` with a `filtered_reason`, instead of dropping them |

### Exit codes

| Code | Meaning                          |
|------|----------------------------------|
| `0`  | Scan completed, no findings      |
| `1`  | Scan completed, findings written |
| `2`  | A fatal error occurred           |

This makes it CI-friendly: a non-zero exit fails the job the moment something
confesses.

## Output

One JSON object per confession, per line. Values are redacted — what's said in the
confessional stays in the confessional — but the SHA-256 of the raw value is
included so you can correlate without storing the secret itself.

```json
{
  "file": "config/app.env",
  "path": "line:3",
  "name_path": "value_pattern",
  "value_path": "value_pattern",
  "name": "ci_note",
  "value": "ghp_********wxyz",
  "raw_value": "ghp_0123456789abcdefghijklmnopqrstuvwxyz",
  "value_sha256": "6675cd0c…",
  "entropy": 4.71,
  "name_value_distance": 38,
  "reason": "gitleaks:github-pat"
}
```

Every finding carries the `entropy` field: the Shannon entropy (bits/symbol) of
the raw value, rounded to two decimals — handy for triage and tuning the
`min_entropy` / `high_entropy_threshold` thresholds.

`name_value_similarity` scores how closely the value resembles its key name, in
`[0,1]` where `1` is identical. It is the max of normalized Levenshtein and
Jaro-Winkler similarity (both case-insensitive) — Jaro-Winkler rewards the shared
prefixes typical of placeholder mutations (`secret`/`secrets`,
`passwd`/`passw0rd`). A high score flags a value echoing its key; a low one
points to a genuine opaque secret. Set the rule's `max_name_value_similarity` to
drop name-driven findings at or above a chosen similarity (`0` disables it).

The `reason` field explains why it was flagged — e.g. `jwt_indicator`,
`url_credentials`, `private_key_indicator`, a name-driven message, or
`gitleaks:<rule-id>` for a value-pattern match. JWT values also carry a `meta`
object with parsed claims (`issuer`, `iat`, `expiration`, `is_expired`, and any
remaining claims under `extra`).

## Scanning source code

Beyond structured config, confessecrets scans source files in **Python**,
**JavaScript/TypeScript**, **Go**, **Java**, **C#**, **Ruby**, **PHP**,
**Kotlin**, and **Rust**. It parses each file with
[tree-sitter](https://tree-sitter.github.io/) and inspects the *syntax* of each
assignment, which lets it avoid the classic false positive that trips up
regex-only scanners:

```python
password = "hunter2supersecret"               # flagged — value is a string literal
api_token = os.environ.get("API_TOKEN")       # not flagged — value is a runtime lookup
secret = f"sk_{var}"                          # not flagged — interpolated, not a literal
```

Detection covers several shapes:

- **name-driven** — a secret-looking variable assigned a string literal
  (`password = "…"`).
- **value-driven** — any string literal whose shape matches a gitleaks pattern,
  regardless of the surrounding name (`"AKIA…"`, `"ghp_…"`).
- **env fallback** — a hardcoded default behind an environment/config lookup,
  whether passed as an argument (`os.getenv("DB_PASSWORD", "hunter2")`) or via a
  logical default (`process.env.API_KEY || "fallback"`, `GetEnvironmentVariable(…) ?? "fallback"`).
- **call argument** — a secret passed into any call when the assignment target
  signals a secret (`password = vault.fetch("key", "s3cr3t!")`).

Because it reads the syntax tree, it skips what regex scanners get wrong: runtime
lookups (the value is a *call*), interpolated/dynamic strings (f-strings, template
literals), and comparisons (`process.env.MODE == "prod"` is not a default). Call
arguments and defaults are gated more strictly to avoid flagging prompts and
labels (e.g. `getpass("Enter password: ")`).

### No setup required

Parsing uses a pure-Go tree-sitter runtime
([gotreesitter](https://github.com/odvcencio/gotreesitter)) with the grammars
**embedded in the binary**. There is nothing to install, download, or compile —
no `libtree-sitter`, no per-language grammar libraries, no C toolchain. The build
stays CGO-free, so `confessecrets` cross-compiles to any `GOOS`/`GOARCH` from a
single machine (`CGO_ENABLED=0`).

To actually scan source files, add their globs to the config `allow` list (e.g.
`"**/*.py"`, `"**/*.go"`); the default `config.yaml` already includes them.

> Note: `.tsx` is parsed with the TypeScript grammar, which does not understand
> JSX; embedded-JSX files may parse partially.

## Configuration

The config (default `config.yaml`) decides whose confessions you hear — which
files are scanned and what actually counts as a secret worth flagging.

```yaml
files:
  allow:                 # glob patterns to scan (doublestar syntax)
    - "**/*.json"
    - "**/*.yaml"
    - "**/*.yml"
    - "**/.env"
    - "**/.env.*"
    - "**/*.env"
    - "**/*.xml"
    - "**/*.properties"
    - "**/*.ini"
  deny:                  # glob patterns to skip (checked before allow)
    - "**/test/**"
    - "**/.git/**"
    - "**/node_modules/**"

rules:
  - name_paths: [name, key, field]      # keys that may name a secret (structured)
    value_paths: [value, val, secret]   # sibling keys holding the value
    # A name matching ANY entry signals a secret. Each entry is either a bare
    # regex string or a {name, regex} mapping (the name is a label for the rule).
    name_regexes:
      - '(?i)(secret|token|api[_-]?key|password|credential|auth)'
      - name: camelcase-key
        regex: '(?-i:[a-z0-9]Key([A-Z0-9_]|$))'
    min_value_len: 8                     # default 8 when omitted
    min_entropy: 2.0                     # gate: drop low-variety placeholders (0 = off)
    high_entropy_threshold: 0            # flag any opaque value this random (0 = off)
    max_name_value_similarity: 0.85      # drop values this similar to the name (0 = off)

    # Names matching any of these are never treated as secrets, even if they
    # match a name pattern (e.g. "label"/"labelKey").
    ignore_name_patterns:
      - '(?i)(label|text|title|description)'

    # Values starting with these prefixes are ignored (vault refs, placeholders…).
    ignore_value_prefixes:
      - vault://
      - ${

    # Values matching these regexes are ignored.
    ignore_value_patterns:
      - '^ENC\[.*\]$'
      - '^arn:aws:secretsmanager:'
```

Value-pattern (gitleaks) scanning is built in and always on; it honors
`ignore_value_prefixes` / `ignore_value_patterns` so you can suppress
false positives.

Two optional entropy controls measure the Shannon entropy (bits/symbol) of a
value to catch what the name and shape rules miss:

- `min_entropy` is a *gate*: a value flagged only because its key name looks
  secret-y must clear this threshold, so repetitive placeholders (`aaaaaaaa`)
  are dropped. Values with a definite secret reason (JWT, private key, URL
  credentials) bypass the gate.
- `high_entropy_threshold` is a *detector*: any opaque token-like value
  (whitespace-free, ≤200 chars) whose entropy meets it is flagged regardless of
  key name, reported as `high_entropy:<measured>`. Built-in gitleaks and custom
  detectors take precedence, and rule `ignore_*` suppressions still apply. It is
  noisy when scanning source code (many string literals sit near the secret
  range), so it ships disabled; enable it (e.g. `4.5`) for config-only scans
  (`-scan config`). Keep it above ~4.0, where hex digests and UUIDs sit.

`high_entropy_threshold` defaults to `0` (disabled); `min_entropy` is a pure
filter and is safe to leave on.

A value that merely echoes its key name — `password="password"`,
`api_key="your-api-key"`, `token="TOKEN"`, `secret="<my-secret>"` — is treated
as a placeholder and dropped automatically. The comparison ignores case,
separators, camelCase, and common filler words ("your", "my", "example", …), so
these obvious fakes never count as findings.

### Custom value-pattern detectors

Beyond the built-in gitleaks patterns, you can define your own value-shape
detectors using [trufflehog's custom-detector schema](https://trufflesecurity.com/docs/custom-detectors).
Each detector flags a value by its *shape* alone — regardless of the surrounding
key name — and matches are tagged `custom:<name>` in the `reason` field.

```yaml
detectors:
  - name: acme-api-key
    keywords:            # at least one must appear in the value or its key name
      - acme             #   (case-insensitive); omit for an always-on detector
    regex:               # every named regex must match the value
      key: 'AKME-[0-9a-f]{32}'
    primary_regex_name: key       # which regex supplies the reported value
    exclude_regexes_match:        # drop matches whose value matches any of these
      - '^AKME-0+$'
    exclude_words:                # drop a candidate when any of these is present
      - example
    entropy: 3.0                  # require this minimum Shannon entropy (bits/symbol)
```

A detector fires when **at least one keyword** is present (in the value or its key
name) and **every named regex** matches the value. When a regex defines a capture
group, its first group is the reported secret; otherwise the whole match is.
`primary_regex_name` (optional) selects which regex's match is reported and
entropy/exclude-checked, defaulting to the alphabetically first. The
`exclude_*` and `entropy` fields are optional false-positive filters. Custom
detectors honor the same `ignore_value_prefixes` / `ignore_value_patterns`
suppressions as the built-in patterns, and a built-in gitleaks match takes
precedence over a custom one for the same value.

Notes:

- Detection is per **value**: a multi-regex detector requires every regex to
  match the *same* scalar value (most custom detectors use a single regex).
- Live HTTP `verify` endpoints from trufflehog's schema are **not** supported —
  confessecrets is an offline scanner that redacts values rather than sending
  them anywhere — so that field is ignored if present.

### Custom filter

A top-level `filter` is an [expr-lang](https://expr-lang.org) expression evaluated
against every finding; when it is **true**, the finding is dropped. It's a flexible
way to suppress whole classes of false positives by their computed properties:

```yaml
# Drop low-entropy values whose name closely echoes the value.
filter: 'entropy <= 4 && name_value_similarity > 0.65'
```

The variables available to an expression are:

| Variable | Type | Meaning |
| --- | --- | --- |
| `entropy` | number | Shannon entropy of the value (bits/symbol) |
| `name_value_similarity` | number | name/value similarity, `0..1` |
| `value_length` | number | length of the raw value in bytes |
| `name` | string | the key name |
| `value` | string | the raw (unredacted) value |
| `reason` | string | why the value was flagged |
| `file`, `path`, `name_path`, `value_path` | string | location fields |

expr-lang operators and built-ins work too, so richer rules like
`value matches "(?i)example$"`, `name contains "test"`, or
`reason startsWith "gitleaks:"` are valid. The expression is type-checked at load
time, so a bad filter fails fast. Leave it empty to disable.

To see what a filter is removing, run with `-show-filtered`: excluded findings are
kept in the output with `"filtered": true` and a `"filtered_reason"` holding the
matched expression, rather than being dropped. Filtered findings are informational
and do **not** affect the exit code, so a scan whose only findings are filtered
still exits `0`.

### Repo-local config

When the scan descends into a **repository root** — a directory containing a
`.git` entry (a normal clone, or a `.git` *file* for worktrees/submodules) — the
scanner looks for a repo-local config there and uses it for every file in that
repository. The file names checked, in order, are:

```
.confessecrets.yaml
.confessecrets.yml
```

This lets each repository carry its own allow/deny globs and rules (e.g. an
internal repo that wants stricter rules, or one that needs extra
`ignore_value_*` entries). A repo-local config has the same shape as the main
config and fully replaces the base config for that repository's files.

Semantics:

- A repository **boundary** is respected: a repo *without* its own config uses
  the base `-config`, even if a parent repository defines one. Nested repos use
  the config of their **nearest** enclosing repository.
- A repo-local config that fails to load or compile is reported to stderr and
  skipped — the scan continues with the base config for that repo.
- Pass `-repo-config=false` to ignore repo-local configs entirely and apply the
  base `-config` everywhere.

## Test

```sh
go test ./...
go vet ./...
```

## Project layout

```
cmd/confessecrets/   CLI entry point (flag parsing, output)
pkg/scanner/        library: config, file walking, detection
  models.go         types (Config, Rule, RuleSet, Finding, Meta, Detector…)
  files.go          config loading/compiling, file walking/filtering, format dispatch
  detect.go         per-format detectors + classification helpers
  patterns.go       gitleaks-style value patterns
  detectors.go      custom (trufflehog-style) value-pattern detectors
```
