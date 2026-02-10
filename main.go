// secret-detector-export combines TruffleHog verification hosts and Gitleaks
// regex patterns into a unified secret detection dataset for Gondolin.
//
// From TruffleHog (AGPL-3.0): Only verification URLs/hosts are extracted
// (factual data, not copyrightable). No regex patterns are copied.
//
// From Gitleaks (MIT): Regex patterns, keywords, and metadata are extracted.
// MIT license allows free embedding with attribution.
//
// Each service gets a "keyword" derived from its name that can be used to
// match env var names (e.g., keyword "cloudflare" matches CLOUDFLARE_API_KEY).
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

type RunStats struct {
	Mode     string             `json:"mode"`
	Combined CombinedStats      `json:"combined"`
	Gondolin *GondolinModeStats `json:"gondolin,omitempty"`
}

type GondolinModeStats struct {
	KeywordHostMappings int `json:"keyword_host_mappings"`
	ExactNameMappings   int `json:"exact_name_mappings"`
	ValuePatterns       int `json:"value_patterns"`
	LinkedPatterns      int `json:"linked_patterns"`
}

func main() {
	thDir := flag.String("trufflehog", "", "Path to trufflehog/pkg/detectors/")
	glPath := flag.String("gitleaks", "", "Path to gitleaks/config/gitleaks.toml")
	fromFull := flag.String("from-full", "", "Read CombinedExport JSON from this file instead of extracting from -trufflehog/-gitleaks")
	outPath := flag.String("out", "-", "Output file path (or - for stdout)")
	mode := flag.String("mode", "full", "Output mode: 'full' (combined dataset) or 'gondolin' (slim runtime dataset)")
	force := flag.Bool("force", false, "Overwrite -out if it already exists")
	strict := flag.Bool("strict", false, "Treat TruffleHog URL/host extraction warnings as errors")
	allowIPHosts := flag.Bool("allow-ip-hosts", false, "Allow exporting IP-literal hosts (unsafe; default: false)")
	syncDir := flag.Bool("sync-dir", false, "fsync output directory after atomic writes (durability over speed)")
	statsJSON := flag.String("stats-json", "", "Optional file path to write machine-readable run stats JSON")
	flag.Parse()

	if *mode != "full" && *mode != "gondolin" {
		exitErr(fmt.Errorf("invalid -mode %q: must be 'full' or 'gondolin'", *mode))
	}

	if *fromFull != "" && (*thDir != "" || *glPath != "") {
		exitErr(errors.New("-from-full cannot be combined with -trufflehog or -gitleaks"))
	}
	if *fromFull == "" && *thDir == "" && *glPath == "" {
		exitErr(errors.New("at least one of -from-full or (-trufflehog / -gitleaks) is required"))
	}

	var export CombinedExport
	if *fromFull != "" {
		data, err := os.ReadFile(*fromFull)
		if err != nil {
			exitErr(fmt.Errorf("read -from-full: %w", err))
		}
		if err := json.Unmarshal(data, &export); err != nil {
			exitErr(fmt.Errorf("decode -from-full JSON: %w", err))
		}
	} else {
		var thDetectors []THDetector
		var glRules []GLRule

		if *thDir != "" {
			var skipped []string
			var warnings []error
			var err error
			thDetectors, skipped, warnings, err = extractTrufflehogDetectors(*thDir, THExtractOptions{AllowIPHosts: *allowIPHosts})
			if err != nil {
				exitErr(fmt.Errorf("trufflehog extraction: %w", err))
			}
			if len(skipped) > 0 {
				fmt.Fprintf(os.Stderr, "TruffleHog: skipped %d detectors\n", len(skipped))
			}
			if len(warnings) > 0 {
				fmt.Fprintf(os.Stderr, "TruffleHog: %d warnings (showing up to 5):\n", len(warnings))
				for i := 0; i < len(warnings) && i < 5; i++ {
					fmt.Fprintf(os.Stderr, "  - %v\n", warnings[i])
				}
				if *strict {
					exitErr(fmt.Errorf("trufflehog extraction produced %d warnings (first: %v)", len(warnings), warnings[0]))
				}
			}
			fmt.Fprintf(os.Stderr, "TruffleHog: extracted %d detectors with hosts\n", len(thDetectors))
		}

		if *glPath != "" {
			var err error
			glRules, err = extractGitleaksRules(*glPath)
			if err != nil {
				exitErr(fmt.Errorf("gitleaks extraction: %w", err))
			}
			fmt.Fprintf(os.Stderr, "Gitleaks: extracted %d rules\n", len(glRules))
		}

		export = combine(thDetectors, glRules)
	}

	// Choose output payload based on mode
	var output any
	var gondolinStats *GondolinModeStats
	switch *mode {
	case "gondolin":
		gondolin := toGondolinExport(export)
		linkedPatterns := countLinkedPatterns(gondolin.ValuePatterns)
		gondolinStats = &GondolinModeStats{
			KeywordHostMappings: len(gondolin.KeywordHostMap),
			ExactNameMappings:   len(gondolin.ExactNameHostMap),
			ValuePatterns:       len(gondolin.ValuePatterns),
			LinkedPatterns:      linkedPatterns,
		}
		output = gondolin
		fmt.Fprintf(os.Stderr, "\n=== Gondolin Export ===\n")
		fmt.Fprintf(os.Stderr, "Keyword→host mappings: %d\n", gondolinStats.KeywordHostMappings)
		fmt.Fprintf(os.Stderr, "Exact-name mappings:   %d\n", gondolinStats.ExactNameMappings)
		fmt.Fprintf(os.Stderr, "Value patterns:        %d (with host linkage: %d)\n",
			gondolinStats.ValuePatterns, gondolinStats.LinkedPatterns)
	default:
		output = export
	}

	if *outPath == "-" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(output); err != nil {
			exitErr(fmt.Errorf("encode json: %w", err))
		}
	} else {
		if err := writeJSONAtomic(*outPath, *force, *syncDir, output); err != nil {
			exitErr(err)
		}
	}

	// Print full summary (always useful on stderr)
	s := export.Stats
	fmt.Fprintf(os.Stderr, "\n=== Summary ===\n")
	fmt.Fprintf(os.Stderr, "Total services:       %d\n", s.TotalServices)
	fmt.Fprintf(os.Stderr, "  With hosts+rules:   %d (exact:%d prefix:%d alias:%d)\n",
		s.ServicesWithHosts, s.MatchExact, s.MatchPrefix, s.MatchAlias)
	fmt.Fprintf(os.Stderr, "  Rules only (no host):%d\n", s.ServicesNoHosts)
	fmt.Fprintf(os.Stderr, "  Hosts only (no rule):%d\n", s.THOnlyServices)
	fmt.Fprintf(os.Stderr, "Total GL rules:       %d (%d with hosts)\n", s.TotalRules, s.RulesWithHosts)

	if *statsJSON != "" {
		runStats := RunStats{
			Mode:     *mode,
			Combined: export.Stats,
			Gondolin: gondolinStats,
		}
		if err := writeJSONAtomic(*statsJSON, true, *syncDir, runStats); err != nil {
			exitErr(fmt.Errorf("write stats json: %w", err))
		}
	}
}

func writeJSONAtomic(outPath string, force bool, syncDir bool, v any) error {
	if !force {
		if _, err := os.Stat(outPath); err == nil {
			return fmt.Errorf("output file already exists: %s (use -force to overwrite)", outPath)
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("stat output: %w", err)
		}
	}

	dir := filepath.Dir(outPath)
	base := filepath.Base(outPath)
	f, err := os.CreateTemp(dir, base+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp output: %w", err)
	}
	tmpPath := f.Name()
	cleanup := func() { _ = os.Remove(tmpPath) }

	if err := f.Chmod(0o644); err != nil {
		_ = f.Close()
		cleanup()
		return fmt.Errorf("chmod temp output: %w", err)
	}

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		_ = f.Close()
		cleanup()
		return fmt.Errorf("encode json: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		cleanup()
		return fmt.Errorf("sync temp output: %w", err)
	}
	if err := f.Close(); err != nil {
		cleanup()
		return fmt.Errorf("close temp output: %w", err)
	}

	// On Windows, Rename won't overwrite existing files.
	if force {
		_ = os.Remove(outPath)
	}

	if err := os.Rename(tmpPath, outPath); err != nil {
		cleanup()
		return fmt.Errorf("rename temp output: %w", err)
	}

	// Optional: sync the directory entry for stronger durability guarantees.
	if syncDir {
		if df, err := os.Open(dir); err == nil {
			_ = df.Sync()
			_ = df.Close()
		}
	}

	return nil
}

func countLinkedPatterns(patterns []ValuePattern) int {
	n := 0
	for _, p := range patterns {
		if p.Keyword != "" {
			n++
		}
	}
	return n
}

func exitErr(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
