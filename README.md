# confesecrets

A secret scanner for **structured configuration files**. It walks a file or
directory and reports likely secrets as newline-delimited JSON (NDJSON).

It detects secrets two complementary ways:

- **Name-driven** — a key whose name matches a configured regex (e.g. `password`,
  `api_key`, `client_secret`) paired with a populated, secret-looking value.
- **Value-driven** — a value whose *shape* matches a known secret token
  (gitleaks-style patterns such as `AKIA…`, `ghp_…`, `sk_live_…`), regardless of
  its key name.

Supported formats: **JSON / JSONC**, **YAML**, **XML**, **dotenv**
(`.env`, `.env.*`, `*.env`), **Java properties** (`.properties`), and
**INI** (`.ini`).

## Requirements

- Go **1.26+** (see `go.mod`)

## Build

```sh
# Build a binary into ./confesecrets
go build -o confesecrets ./cmd/confesecrets

# Or install it onto your PATH (into $GOBIN / $GOPATH/bin)
go install github.com/rezen/confesecrets/cmd/confesecrets@latest
```

## Run

The scanner is the `cmd/confesecrets` package — run the **package**, not a single
file:

```sh
# From source
go run ./cmd/confesecrets -config config.yaml -path ./path/to/scan

# Or with the built binary
./confesecrets -config config.yaml -path ./path/to/scan
```

> Note: `go run main.go` will fail — the program is split across several files in
> the package. Use `go run ./cmd/confesecrets` (or `go run .` from inside that
> directory).

Findings are written as NDJSON to stdout by default. Redirect or `tee` to save:

```sh
go run ./cmd/confesecrets -path ~/repos | tee found.txt
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

This makes it CI-friendly: a non-zero exit fails the job when secrets are found.

## Output

One JSON object per finding, per line. Values are redacted; the SHA-256 of the
raw value is included so you can correlate without storing the secret.

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

The config (default `config.yaml`) controls which files are scanned and what
counts as a secret.

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
cmd/confesecrets/   CLI entry point (flag parsing, output)
pkg/scanner/        library: config, file walking, detection
  models.go         types (Config, Rule, Finding, Meta, Detector…)
  files.go          config loading, file walking/filtering, format dispatch
  detect.go         per-format detectors + classification helpers
  patterns.go       gitleaks-style value patterns
```
