package main

import (
	"sort"
	"strings"
	"time"
)

// --- Output types ---

type CombinedExport struct {
	GeneratedAt time.Time     `json:"generated_at"`
	Stats       CombinedStats `json:"stats"`
	Services    []CombinedSvc `json:"services"`
	THOnlyHosts []THOnlyEntry `json:"th_only_hosts,omitempty"` // TH detectors with no GL match
	GLNoHosts   []string      `json:"gl_no_hosts,omitempty"`   // GL services with no TH host
}

type CombinedStats struct {
	TotalServices     int `json:"total_services"`      // GL services + TH-only services
	ServicesWithHosts int `json:"services_with_hosts"` // have both regex and hosts
	ServicesNoHosts   int `json:"services_no_hosts"`   // GL rules but no TH hosts
	THOnlyServices    int `json:"th_only_services"`    // TH hosts but no GL rules
	TotalRules        int `json:"total_rules"`         // GL rules total
	RulesWithHosts    int `json:"rules_with_hosts"`
	MatchExact        int `json:"match_exact"`
	MatchPrefix       int `json:"match_prefix"`
	MatchAlias        int `json:"match_alias"`
}

// CombinedSvc is a service entry in the combined output. It has:
// - A canonical keyword (used for env var name matching)
// - Hosts from TruffleHog (for createHttpHooks)
// - Regex rules from Gitleaks (for value-based detection)
type CombinedSvc struct {
	Keyword   string         `json:"keyword"`              // canonical service keyword
	Hosts     []string       `json:"hosts,omitempty"`      // from TruffleHog
	MatchType string         `json:"match_type,omitempty"` // "exact", "prefix", "alias", ""
	MatchedTH []string       `json:"matched_th,omitempty"` // TH dir names that matched
	Rules     []CombinedRule `json:"rules"`                // from Gitleaks
}

type CombinedRule struct {
	ID          string   `json:"id"`
	Description string   `json:"description,omitempty"`
	Regex       string   `json:"regex"`
	Entropy     float64  `json:"entropy,omitempty"`
	SecretGroup int      `json:"secret_group,omitempty"`
	Keywords    []string `json:"keywords,omitempty"`
}

// THOnlyEntry is a TruffleHog detector that has hosts but no matching GL rules.
// These are still useful: the keyword can match env var names.
type THOnlyEntry struct {
	Keyword string   `json:"keyword"`
	DirName string   `json:"dir_name"`
	Hosts   []string `json:"hosts"`
}

// combine merges TruffleHog detectors and Gitleaks rules into a unified dataset.
//
// The matching strategy:
//  1. Build a keyword→hosts index from TH detectors (using deriveKeywordFromTHName)
//  2. For each GL service keyword, find matching TH entries:
//     a. Exact match on keyword (after normalization)
//     b. Manual alias lookup
//     c. Prefix match (GL keyword is prefix of TH keyword, len≥4)
//  3. TH detectors with no GL match go into THOnlyHosts
func combine(thDetectors []THDetector, glRules []GLRule) CombinedExport {
	// Index TH detectors by normalized keyword → list of detectors
	thByKeyword := make(map[string][]thEntry)
	thUsed := make(map[string]bool) // track which TH dirs are claimed

	for _, d := range thDetectors {
		norm := normalizeKeyword(d.Keyword)
		thByKeyword[norm] = append(thByKeyword[norm], thEntry{
			dirName: d.DirName,
			hosts:   d.Hosts,
		})
	}

	// Group GL rules by keyword
	type glGroup struct {
		keyword string
		rules   []GLRule
	}
	glGroupMap := make(map[string]*glGroup)
	var glKeywords []string

	for _, r := range glRules {
		norm := normalizeKeyword(r.Keyword)
		if g, ok := glGroupMap[norm]; ok {
			g.rules = append(g.rules, r)
		} else {
			glGroupMap[norm] = &glGroup{keyword: r.Keyword, rules: []GLRule{r}}
			glKeywords = append(glKeywords, norm)
		}
	}
	sort.Strings(glKeywords)

	thKeywordsSorted := sortedKeysFromEntries(thByKeyword)

	// Match GL groups to TH entries
	var services []CombinedSvc
	var stats CombinedStats
	var glNoHosts []string

	for _, normKey := range glKeywords {
		glg := glGroupMap[normKey]
		matchedTH, matchType := findTHMatch(glg.keyword, thByKeyword, thKeywordsSorted)

		// Collect hosts and mark TH entries as used
		hostSet := make(map[string]bool)
		var matchedNames []string
		for _, m := range matchedTH {
			if entries, ok := thByKeyword[normalizeKeyword(m)]; ok {
				for _, e := range entries {
					for _, h := range e.hosts {
						hostSet[h] = true
					}
					thUsed[e.dirName] = true
					matchedNames = append(matchedNames, e.dirName)
				}
			}
		}

		hosts := sortedKeys(hostSet)
		sort.Strings(matchedNames)

		// Build rules
		combinedRules := make([]CombinedRule, len(glg.rules))
		for i, r := range glg.rules {
			combinedRules[i] = CombinedRule{
				ID:          r.ID,
				Description: r.Description,
				Regex:       r.Regex,
				Entropy:     r.Entropy,
				SecretGroup: r.SecretGroup,
				Keywords:    r.Keywords,
			}
		}

		svc := CombinedSvc{
			Keyword:   glg.keyword,
			Hosts:     hosts,
			MatchType: matchType,
			MatchedTH: matchedNames,
			Rules:     combinedRules,
		}
		services = append(services, svc)

		stats.TotalRules += len(glg.rules)
		if len(hosts) > 0 {
			stats.ServicesWithHosts++
			stats.RulesWithHosts += len(glg.rules)
			switch matchType {
			case "exact":
				stats.MatchExact++
			case "prefix":
				stats.MatchPrefix++
			case "alias":
				stats.MatchAlias++
			}
		} else {
			stats.ServicesNoHosts++
			glNoHosts = append(glNoHosts, glg.keyword)
		}
	}

	// Collect TH-only entries (hosts with no GL rules)
	var thOnly []THOnlyEntry
	for _, d := range thDetectors {
		if !thUsed[d.DirName] {
			thOnly = append(thOnly, THOnlyEntry{
				Keyword: d.Keyword,
				DirName: d.DirName,
				Hosts:   d.Hosts,
			})
		}
	}
	sort.Slice(thOnly, func(i, j int) bool {
		return thOnly[i].Keyword < thOnly[j].Keyword
	})

	stats.TotalServices = len(services) + len(thOnly)
	stats.THOnlyServices = len(thOnly)

	sort.Strings(glNoHosts)

	return CombinedExport{
		GeneratedAt: time.Now().UTC(),
		Stats:       stats,
		Services:    services,
		THOnlyHosts: thOnly,
		GLNoHosts:   glNoHosts,
	}
}

// findTHMatch finds TruffleHog keyword matches for a Gitleaks service keyword.
// Returns (list of matched TH normalized keywords, match type).
func findTHMatch(glKeyword string, thByKeyword map[string][]thEntry, thKeywordsSorted []string) ([]string, string) {
	glNorm := normalizeKeyword(glKeyword)

	// Strategy 1: Exact match
	if _, ok := thByKeyword[glNorm]; ok {
		return []string{glNorm}, "exact"
	}

	// Strategy 2: Manual alias
	if alias, ok := serviceAliasesByNorm[glNorm]; ok {
		aliasNorm := normalizeKeyword(alias)
		if _, ok := thByKeyword[aliasNorm]; ok {
			return []string{aliasNorm}, "alias"
		}
	}

	// Strategy 3: Prefix match — find TH keywords that start with the GL keyword
	// Only for keywords >= 4 chars to avoid false positives
	if len(glNorm) >= 4 {
		matches := prefixMatchesSorted(thKeywordsSorted, glNorm)
		if len(matches) > 0 {
			return matches, "prefix"
		}
	}

	return nil, ""
}

type thEntry struct {
	dirName string
	hosts   []string
}

func sortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sortedKeysFromEntries(m map[string][]thEntry) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func prefixMatchesSorted(sorted []string, prefix string) []string {
	start := sort.Search(len(sorted), func(i int) bool {
		return sorted[i] >= prefix
	})
	if start >= len(sorted) {
		return nil
	}
	var out []string
	for i := start; i < len(sorted); i++ {
		k := sorted[i]
		if !strings.HasPrefix(k, prefix) {
			break
		}
		if k == prefix {
			continue
		}
		out = append(out, k)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
