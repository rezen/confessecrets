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

Supported formats: **JSON / JSONC**, **YAML**, **XML**, **dotenv**
(`.env`, `.env.*`, `*.env`), **Java properties** (`.properties`), and
**INI** (`.ini`).

## Requirements

- Go **1.26+** (see `go.mod`)

## Build

```sh
# Build a binary into ./confessecrets
go build -o confessecrets ./cmd/confessecrets

# Or install it onto your PATH (into $GOBIN / $GOPATH/bin)
go install github.com/rezen/confessecrets/cmd/confessecrets@latest
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

| Flag      | Default       | Description                                   |
|-----------|---------------|-----------------------------------------------|
| `-config` | `config.yaml` | Path to the scanner config                    |
| `-path`   | `.`           | File or directory to scan                     |
| `-output` | `-`           | Output file, or `-` for stdout                |

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
  "reason": "gitleaks:github-pat"
}
```

The `reason` field explains why it was flagged — e.g. `jwt_indicator`,
`url_credentials`, `private_key_indicator`, a name-driven message, or
`gitleaks:<rule-id>` for a value-pattern match. JWT values also carry a `meta`
object with parsed claims (`issuer`, `iat`, `expiration`, `is_expired`, and any
remaining claims under `extra`).

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
    name_regex: '(?i)(secret|token|api[_-]?key|password|credential|auth)'
    min_value_len: 8                     # default 8 when omitted

    # Names matching any of these are never treated as secrets, even if they
    # match name_regex (e.g. "label"/"labelKey" matching the "key" alternative).
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

## Test

```sh
go test ./...
go vet ./...
```

## Project layout

```
cmd/confessecrets/   CLI entry point (flag parsing, output)
pkg/scanner/        library: config, file walking, detection
  models.go         types (Config, Rule, Finding, Meta, Detector…)
  files.go          config loading, file walking/filtering, format dispatch
  detect.go         per-format detectors + classification helpers
  patterns.go       gitleaks-style value patterns
```
