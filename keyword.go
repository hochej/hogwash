package main

import "strings"

// credentialSuffixes are concatenated credential-type words that TruffleHog
// appends to service names in its directory structure. Ordered longest-first
// so we greedily strip the longest match.
//
// Example: "cloudflareapitoken" → strip "apitoken" → "cloudflare"
//          "airtablepersonalaccesstoken" → strip "personalaccesstoken" → "airtable"
var credentialSuffixes = []string{
	// Long compound suffixes (must come before their shorter components)
	"personalaccesstoken",
	"personaltoken",
	"personalapikey",
	"organizationapi",
	"globalapikey",
	"apppassword",
	"consumerkey",
	"orgtoken",
	"bottoken",
	"accesstoken",
	"apitokenv2",
	"apitoken",
	"apikey",
	"api",
	"oauth2",
	"oauth",
	"webhook",
	"tokenv2",
	"tokenv3",
	"token",
	"cakey",
	"key",
	// Version suffixes
	"v2",
	"v3",
	// Platform suffixes — note: "io" intentionally excluded because many
	// services are .io domains (frame.io, fly.io, keen.io etc.)
	"cloud",
	"license",
}

// credentialWords are individual words that describe a credential type rather
// than a service. Used for splitting hyphenated Gitleaks rule IDs.
var credentialWords = map[string]bool{
	// Core credential nouns
	"api": true, "key": true, "token": true, "secret": true,
	"password": true, "credential": true, "credentials": true,

	// Auth-related
	"access": true, "auth": true, "authentication": true,
	"oauth": true, "pat": true, "sso": true, "scim": true,

	// Roles / scopes
	"admin": true, "user": true, "client": true, "service": true,
	"bot": true, "app": true, "org": true, "organization": true,
	"account": true, "personal": true, "personnal": true, // gitleaks typo

	// Modifiers
	"public": true, "pub": true, "private": true, "global": true,
	"shared": true, "custom": true, "sensitive": true,
	"long": true, "short": true, "lived": true,
	"fine": true, "grained": true,
	"legacy": true, "workspace": true, "routable": true,
	"test": true, "batch": true, "bearer": true,

	// Infra / CI credential types
	"deploy": true, "runner": true, "cicd": true, "job": true,
	"trigger": true, "registration": true, "pipeline": true,
	"feed": true, "incoming": true, "session": true, "cookie": true,
	"kubernetes": true, "agent": true, "feature": true, "flag": true,
	"cloud": true, "upload": true, "reference": true, "identity": true,

	// Crypto / format
	"signing": true, "encryption": true, "ca": true, "origin": true,
	"insert": true, "browser": true, "base64": true,
	"config": true, "refresh": true,

	// Web
	"webhook": true, "url": true, "header": true, "page": true,

	// Abbreviations used by gitlab
	"ptt": true, "rrt": true,
}

// glServiceOverrides maps Gitleaks derived service names to canonical keywords
// for cases where the heuristic gives the wrong result.
var glServiceOverrides = map[string]string{
	"aws-amazon-bedrock":     "aws",
	"contentful-delivery":    "contentful",
	"curl":                   "curl",
	"hashicorp-tf":           "hashicorp",
	"microsoft-teams":        "microsoft-teams",
	"new-relic":              "newrelic",
	"settlemint-application": "settlemint",
	"yandex-aws":             "yandex",
}

// thKeywordOverrides maps TruffleHog directory names to canonical keywords
// for cases where suffix-stripping doesn't work.
var thKeywordOverrides = map[string]string{
	// Names where suffix stripping is ambiguous or wrong
	"gcpapplicationdefaultcredentials": "gcp",
	"hubspot_apikey":                  "hubspot",
	// io suffix would incorrectly strip
	"adafruitio": "adafruit",
	"adobeio":    "adobe",
	"flyio":      "flyio",    // "fly" is too short/ambiguous, keep as flyio
	"frameio":    "frameio",  // frame.io is the service name
	// key suffix would strip to "private" which is too generic
	"privatekey": "privatekey",
	// meraki stays as-is; GL "cisco-meraki" maps to it via serviceAliases
	// "meraki": "meraki", // implicit, no override needed
	// Compound names that should map to a broader service
	"sonarcloud": "sonar",
}

// serviceAliases maps a Gitleaks canonical keyword to a TruffleHog-derived
// keyword for cases where the names diverge after normalization.
//
// Keys are normalized at init time so callers can look up by normalized
// keyword and avoid case/format brittleness.
var serviceAliases = map[string]string{
	"cisco-meraki":    "meraki",
	"maxmind-license": "maxmind",
	"private-key":     "privatekey",
}

var serviceAliasesByNorm = func() map[string]string {
	m := make(map[string]string, len(serviceAliases))
	for k, v := range serviceAliases {
		m[normalizeKeyword(k)] = v
	}
	return m
}()

// deriveKeywordFromGitleaksID extracts a service keyword from a hyphenated
// Gitleaks rule ID like "openai-api-key" → "openai".
//
// Scans left-to-right and stops at the first credential-type word.
func deriveKeywordFromGitleaksID(ruleID string) string {
	ruleID = strings.ToLower(strings.TrimSpace(ruleID))
	if ruleID == "" {
		return ""
	}
	parts := strings.Split(ruleID, "-")
	var serviceParts []string
	for _, p := range parts {
		if credentialWords[p] {
			break
		}
		serviceParts = append(serviceParts, p)
	}
	if len(serviceParts) == 0 {
		return ruleID
	}
	name := strings.Join(serviceParts, "-")
	if override, ok := glServiceOverrides[name]; ok {
		return override
	}
	return name
}

// deriveKeywordFromTHName extracts a service keyword from a TruffleHog
// detector directory name like "cloudflareapitoken" → "cloudflare".
//
// Tries manual overrides first, then strips known credential suffixes.
func deriveKeywordFromTHName(dirName string) string {
	dirName = strings.ToLower(strings.TrimSpace(dirName))
	if dirName == "" {
		return ""
	}

	// Check manual overrides first
	if override, ok := thKeywordOverrides[dirName]; ok {
		return override
	}

	// Try stripping known credential suffixes (longest first)
	for _, suffix := range credentialSuffixes {
		if strings.HasSuffix(dirName, suffix) {
			base := dirName[:len(dirName)-len(suffix)]
			if len(base) >= 3 { // avoid stripping to nothing or too-short names
				return base
			}
		}
	}

	return dirName
}

// normalizeKeyword strips hyphens/underscores for fuzzy comparison.
func normalizeKeyword(s string) string {
	s = strings.ToLower(s)
	s = strings.ReplaceAll(s, "-", "")
	s = strings.ReplaceAll(s, "_", "")
	return s
}
