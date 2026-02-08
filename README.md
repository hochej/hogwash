# hogwash

![sniffmerge office](assets/2026-02-08-22-36-00-sniffmerge-office.png)

Scrappy little tool that mashes [TruffleHog](https://github.com/trufflesecurity/trufflehog) and [Gitleaks](https://github.com/gitleaks/gitleaks) together so you get one JSON with service keywords, API hosts, and regex patterns. Built for [Gondolin](https://github.com/earendil-works/gondolin)'s secret-aware env forwarding, but the full dump is there too if you want it.

TruffleHog gives us the hosts, Gitleaks gives us the regexes. We don't import either project — just read their files as data.

## Quick start

```bash
git clone --depth=1 https://github.com/trufflesecurity/trufflehog.git
git clone --depth=1 https://github.com/gitleaks/gitleaks.git

go build -o hogwash .

# slim gondolin export (~47 KB)
./hogwash -trufflehog ./trufflehog/pkg/detectors/ \
          -gitleaks ./gitleaks/config/gitleaks.toml \
          -mode gondolin -out gondolin.json -force

# full dump (~136 KB, everything we extracted)
./hogwash -trufflehog ./trufflehog/pkg/detectors/ \
          -gitleaks ./gitleaks/config/gitleaks.toml \
          -mode full -out full.json -force
```

CI runs weekly and publishes both as release artifacts.

## Modes

**`-mode gondolin`** — what `pi-gondolin.ts` actually consumes:
- `keyword_host_map` — keyword → hosts (substring match on env var names)
- `exact_name_host_map` — for oddballs like `DD_API_KEY`, `HF_TOKEN`
- `value_patterns[]` — regexes that detect secrets by value (e.g. `ghp_`, `sk_live_`)

**`-mode full`** — everything, including matching metadata, TH-only hosts, GL-only rules.

## Tests

```bash
go test -v ./...
```

## License

MIT. Gitleaks patterns are MIT-licensed. TruffleHog hosts are factual data.
