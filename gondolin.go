package main

import (
	_ "embed"
	"encoding/json"
	"sort"
	"time"
)

// --- Gondolin-specific output types ---

// GondolinExport is the slim, purpose-built dataset for Gondolin's
// secret-aware env forwarding. It contains only what pi-gondolin.ts needs:
//   - keyword_host_map:   keyword substring → API hosts (for env var name matching)
//   - exact_name_host_map: full env var name → API hosts (for oddballs like DD_API_KEY)
//   - value_patterns:     Gitleaks regexes for value-based secret detection
type GondolinExport struct {
	SchemaVersion    int                 `json:"schema_version"`
	GeneratedAt      time.Time           `json:"generated_at"`
	KeywordHostMap   map[string][]string `json:"keyword_host_map"`
	ExactNameHostMap map[string][]string `json:"exact_name_host_map"`
	ValuePatterns    []ValuePattern      `json:"value_patterns"`
}

// ValuePattern is a regex-based secret detection rule from Gitleaks,
// stripped to the fields Gondolin actually needs.
type ValuePattern struct {
	ID          string   `json:"id"`
	Keyword     string   `json:"keyword,omitempty"`     // links to keyword_host_map (present only if hosts exist)
	Regex       string   `json:"regex"`
	Keywords    []string `json:"keywords,omitempty"`     // pre-filter hints (skip regex if none match as substring)
	SecretGroup int      `json:"secret_group,omitempty"` // which capture group holds the secret value
}

// exactNameHostMap contains env var names where keyword-based matching doesn't
// work (name too short, too generic, or doesn't contain the service name).
//
// Loaded from data/exact_name_host_map.json so policy data can evolve without
// editing Go source.
//
//go:embed data/exact_name_host_map.json
var exactNameHostMapJSON []byte

var exactNameHostMap = mustLoadExactNameHostMap()

func mustLoadExactNameHostMap() map[string][]string {
	var m map[string][]string
	if err := json.Unmarshal(exactNameHostMapJSON, &m); err != nil {
		panic("invalid embedded exact_name_host_map.json: " + err.Error())
	}
	return m
}

// toGondolinExport transforms a full CombinedExport into the slim Gondolin format.
func toGondolinExport(full CombinedExport) GondolinExport {
	// Build keyword → hosts map from services that have hosts
	keywordHosts := make(map[string][]string)
	// Track which keywords have hosts for linking value patterns
	hasHosts := make(map[string]bool)

	for _, svc := range full.Services {
		if len(svc.Hosts) > 0 {
			keywordHosts[svc.Keyword] = svc.Hosts
			hasHosts[normalizeKeyword(svc.Keyword)] = true
		}
	}

	// Build value patterns from all GL rules
	var patterns []ValuePattern
	for _, svc := range full.Services {
		for _, r := range svc.Rules {
			p := ValuePattern{
				ID:          r.ID,
				Regex:       r.Regex,
				Keywords:    r.Keywords,
				SecretGroup: r.SecretGroup,
			}
			// Only link keyword if there's a host mapping for it
			if hasHosts[normalizeKeyword(svc.Keyword)] {
				p.Keyword = svc.Keyword
			}
			patterns = append(patterns, p)
		}
	}

	// Sort patterns by keyword (empty last), then by ID
	sort.Slice(patterns, func(i, j int) bool {
		ki, kj := patterns[i].Keyword, patterns[j].Keyword
		if ki == "" && kj != "" {
			return false
		}
		if ki != "" && kj == "" {
			return true
		}
		if ki != kj {
			return ki < kj
		}
		return patterns[i].ID < patterns[j].ID
	})

	// Copy exact name map (so we don't expose the package var)
	exactMap := make(map[string][]string, len(exactNameHostMap))
	for k, v := range exactNameHostMap {
		exactMap[k] = v
	}

	return GondolinExport{
		SchemaVersion:    1,
		GeneratedAt:      full.GeneratedAt,
		KeywordHostMap:   keywordHosts,
		ExactNameHostMap: exactMap,
		ValuePatterns:    patterns,
	}
}
