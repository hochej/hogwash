# hogwash

![sniffmerge office](assets/2026-02-08-22-36-00-sniffmerge-office.png)

Extracts secret-detection data from [TruffleHog](https://github.com/trufflesecurity/trufflehog) and [Gitleaks](https://github.com/gitleaks/gitleaks) into a single JSON dataset mapping **service keywords → API hosts + regex patterns**.

- **From TruffleHog (AGPL-3.0):** verification hosts only (factual data, no regex patterns copied)
- **From Gitleaks (MIT):** regex patterns, keywords, entropy thresholds

Each entry gets a canonical **keyword** (e.g. `cloudflare`, `stripe`, `github`) derived by stripping credential-type suffixes from both projects' naming conventions. This keyword is what you match against env var names to route secrets.

## Usage

```bash
# Clone the source projects (not included in this repo)
git clone --depth=1 https://github.com/trufflesecurity/trufflehog.git
git clone --depth=1 https://github.com/gitleaks/gitleaks.git

# Build and run
go build -o hogwash .
./hogwash \
  -trufflehog ./trufflehog/pkg/detectors/ \
  -gitleaks ./gitleaks/config/gitleaks.toml \
  -out combined-output.json
# add -force to overwrite an existing output file
```

## Output

```
Total services:       795
  With hosts+rules:   79 (exact:77 prefix:0 alias:2)
  Rules only (no host):50
  Hosts only (no rule):666
Total GL rules:       221 (147 with hosts)
```

The JSON contains:
- **`services[]`** — entries with both regex rules (from Gitleaks) and hosts (from TruffleHog)
- **`th_only_hosts[]`** — keyword→host mappings for 666 additional services without regex rules

Example entry:

```json
{
  "keyword": "cloudflare",
  "hosts": ["api.cloudflare.com"],
  "match_type": "exact",
  "matched_th": ["cloudflareapitoken", "cloudflarecakey", "cloudflareglobalapikey"],
  "rules": [
    {
      "id": "cloudflare-api-key",
      "regex": "...",
      "keywords": ["cloudflare"]
    }
  ]
}
```

## How matching works

TruffleHog uses concatenated directory names (`cloudflareapitoken`), Gitleaks uses hyphenated rule IDs (`cloudflare-api-key`). Both are reduced to a base keyword:

| Source | Raw name | → Keyword |
|---|---|---|
| TruffleHog | `cloudflareapitoken` | `cloudflare` |
| TruffleHog | `datadogtoken` | `datadog` |
| TruffleHog | `npmtokenv2` | `npm` |
| Gitleaks | `cloudflare-api-key` | `cloudflare` |
| Gitleaks | `new-relic-user-api-key` | `newrelic` |

Three strategies in order: exact match, manual alias, prefix match. A small set of overrides handles edge cases (see `keyword.go`).

## Tests

```bash
# Unit tests (always work)
go test -v ./...

# Integration tests (require cloned repos in ./trufflehog and ./gitleaks)
# or set:
#   TRUFFLEHOG_DIR=/path/to/trufflehog/pkg/detectors
#   GITLEAKS_TOML=/path/to/gitleaks/config/gitleaks.toml

go test -tags=integration -run 'TestCombineIntegration|TestTHKeywordDerivationCoverage' -v
```

## License

This tool is MIT-licensed. It reads TruffleHog and Gitleaks source files as data — it does not link against or import either project.

- Regex patterns in the output originate from **Gitleaks (MIT)** — freely embeddable with attribution
- Hosts in the output are **factual data** extracted from TruffleHog verification URLs — not copyrightable
