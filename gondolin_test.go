package main

import (
	"testing"
	"time"
)

func TestToGondolinExport(t *testing.T) {
	full := CombinedExport{
		GeneratedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Stats:       CombinedStats{TotalServices: 3, ServicesWithHosts: 1, ServicesNoHosts: 1, THOnlyServices: 1},
		Services: []CombinedSvc{
			{
				Keyword:   "stripe",
				Hosts:     []string{"api.stripe.com"},
				MatchType: "exact",
				MatchedTH: []string{"stripe"},
				Rules: []CombinedRule{
					{
						ID:          "stripe-access-token",
						Description: "A Stripe secret key",
						Regex:       `(sk_(?:test|live)_[a-zA-Z0-9]{24,99})`,
						Entropy:     3.5,
						Keywords:    []string{"sk_test", "sk_live"},
					},
				},
			},
			{
				Keyword: "age",
				Rules: []CombinedRule{
					{
						ID:          "age-secret-key",
						Description: "An age secret key",
						Regex:       `AGE-SECRET-KEY-1[0-9A-Z]{58}`,
						Entropy:     3.0,
						SecretGroup: 1,
						Keywords:    []string{"age-secret-key-"},
					},
				},
			},
		},
		THOnlyHosts: []THOnlyEntry{
			{Keyword: "abstract", DirName: "abstract", Hosts: []string{"exchange-rates.abstractapi.com"}},
		},
		GLNoHosts: []string{"age"},
	}

	gondolin := toGondolinExport(full)

	// Schema version
	if gondolin.SchemaVersion != 1 {
		t.Errorf("SchemaVersion = %d, want 1", gondolin.SchemaVersion)
	}

	// Timestamp preserved
	if !gondolin.GeneratedAt.Equal(full.GeneratedAt) {
		t.Errorf("GeneratedAt mismatch")
	}

	// keyword_host_map should include stripe plus policy overrides (aws)
	if len(gondolin.KeywordHostMap) != 2 {
		t.Fatalf("KeywordHostMap length = %d, want 2", len(gondolin.KeywordHostMap))
	}
	if hosts, ok := gondolin.KeywordHostMap["stripe"]; !ok || len(hosts) != 1 || hosts[0] != "api.stripe.com" {
		t.Errorf("KeywordHostMap[stripe] = %v, want [api.stripe.com]", hosts)
	}
	if hosts, ok := gondolin.KeywordHostMap["aws"]; !ok || len(hosts) != 2 || hosts[0] != "sts.amazonaws.com" || hosts[1] != "*.amazonaws.com" {
		t.Errorf("KeywordHostMap[aws] = %v, want [sts.amazonaws.com *.amazonaws.com]", hosts)
	}

	// exact_name_host_map should match the hardcoded map
	if len(gondolin.ExactNameHostMap) != len(exactNameHostMap) {
		t.Errorf("ExactNameHostMap length = %d, want %d", len(gondolin.ExactNameHostMap), len(exactNameHostMap))
	}
	for k, v := range exactNameHostMap {
		got, ok := gondolin.ExactNameHostMap[k]
		if !ok {
			t.Errorf("ExactNameHostMap missing key %q", k)
			continue
		}
		if len(got) != len(v) {
			t.Errorf("ExactNameHostMap[%s] length = %d, want %d", k, len(got), len(v))
		}
	}

	// Value patterns: 2 total (one from stripe, one from age)
	if len(gondolin.ValuePatterns) != 2 {
		t.Fatalf("ValuePatterns length = %d, want 2", len(gondolin.ValuePatterns))
	}

	// Stripe pattern should have keyword linked
	var stripePattern, agePattern *ValuePattern
	for i := range gondolin.ValuePatterns {
		switch gondolin.ValuePatterns[i].ID {
		case "stripe-access-token":
			stripePattern = &gondolin.ValuePatterns[i]
		case "age-secret-key":
			agePattern = &gondolin.ValuePatterns[i]
		}
	}

	if stripePattern == nil {
		t.Fatal("missing stripe-access-token pattern")
	}
	if stripePattern.Keyword != "stripe" {
		t.Errorf("stripe pattern keyword = %q, want 'stripe'", stripePattern.Keyword)
	}
	if stripePattern.Regex == "" {
		t.Error("stripe pattern regex is empty")
	}
	if len(stripePattern.Keywords) != 2 {
		t.Errorf("stripe pattern keywords = %v, want [sk_test sk_live]", stripePattern.Keywords)
	}

	// Age pattern should NOT have keyword (no hosts)
	if agePattern == nil {
		t.Fatal("missing age-secret-key pattern")
	}
	if agePattern.Keyword != "" {
		t.Errorf("age pattern keyword = %q, want empty (no hosts)", agePattern.Keyword)
	}
	if agePattern.SecretGroup != 1 {
		t.Errorf("age pattern secret_group = %d, want 1", agePattern.SecretGroup)
	}

	// No bloat fields should be present (description, entropy, match_type, matched_th, th_only, gl_no_hosts)
	// These are enforced by the type system — GondolinExport simply doesn't have those fields.

	// Patterns with host linkage
	linked := countLinkedPatterns(gondolin.ValuePatterns)
	if linked != 1 {
		t.Errorf("linked patterns = %d, want 1 (only stripe)", linked)
	}
}

func TestToGondolinExportSorting(t *testing.T) {
	full := CombinedExport{
		GeneratedAt: time.Now(),
		Services: []CombinedSvc{
			{
				Keyword: "zebra",
				Rules: []CombinedRule{
					{ID: "zebra-key", Regex: `zebra_[a-z]+`},
				},
			},
			{
				Keyword: "alpha",
				Hosts:   []string{"api.alpha.com"},
				Rules: []CombinedRule{
					{ID: "alpha-key", Regex: `alpha_[a-z]+`, Keywords: []string{"alpha_"}},
				},
			},
		},
	}

	gondolin := toGondolinExport(full)

	// Patterns with keywords sort first, then by keyword, then by ID
	if len(gondolin.ValuePatterns) != 2 {
		t.Fatalf("len = %d, want 2", len(gondolin.ValuePatterns))
	}
	if gondolin.ValuePatterns[0].ID != "alpha-key" {
		t.Errorf("first pattern = %q, want alpha-key (has host linkage, sorts first)", gondolin.ValuePatterns[0].ID)
	}
	if gondolin.ValuePatterns[1].ID != "zebra-key" {
		t.Errorf("second pattern = %q, want zebra-key (no host linkage, sorts last)", gondolin.ValuePatterns[1].ID)
	}
}
