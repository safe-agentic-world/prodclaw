package scan

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"sort"
	"strings"
)

const RulePackVersion = "prodclaw-return-path-v1"

type Finding struct {
	RuleID       string `json:"rule_id"`
	Severity     string `json:"severity"`
	LocationKind string `json:"location_kind"`
	Digest       string `json:"digest"`
}

type rule struct {
	id       string
	severity string
	pattern  *regexp.Regexp
}

var defaultRules = []rule{
	{id: "secret.auth_header", severity: "critical", pattern: regexp.MustCompile(`(?i)authorization:\s*[^\r\n]+`)},
	{id: "secret.cookie_header", severity: "critical", pattern: regexp.MustCompile(`(?i)(set-cookie|cookie):\s*[^\r\n]+`)},
	{id: "secret.bearer_token", severity: "critical", pattern: regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9\-\._~\+\/]{12,}=*`)},
	{id: "secret.jwt", severity: "critical", pattern: regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`)},
	{id: "secret.pem_block", severity: "critical", pattern: regexp.MustCompile(`(?s)-----BEGIN [A-Z ]+-----.*-----END [A-Z ]+-----`)},
	{id: "secret.aws_access_key", severity: "critical", pattern: regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	{id: "prompt.instruction_override", severity: "high", pattern: regexp.MustCompile(`(?i)\b(ignore|disregard|override)\s+(all\s+)?(previous|prior|above)\s+(instructions|messages|rules)\b`)},
	{id: "prompt.credential_exfiltration", severity: "high", pattern: regexp.MustCompile(`(?i)\b(exfiltrate|leak|print|reveal|send)\s+(the\s+)?(secret|token|credential|api key|private key)s?\b`)},
	{id: "prompt.hidden_instructions", severity: "medium", pattern: regexp.MustCompile(`(?i)\b(begin|start)\s+hidden\s+instructions?\b`)},
	{id: "control.hidden_character", severity: "medium", pattern: regexp.MustCompile(`[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]`)},
}

func ScanText(text, locationKind string) []Finding {
	locationKind = normalizeLocationKind(locationKind)
	var findings []Finding
	for _, rule := range defaultRules {
		indexes := rule.pattern.FindAllStringIndex(text, -1)
		for _, match := range indexes {
			if match[0] == match[1] {
				continue
			}
			findings = append(findings, NewFinding(rule.id, rule.severity, locationKind, text[match[0]:match[1]]))
		}
	}
	return DedupeFindings(findings)
}

func StripText(text string) string {
	out := text
	for _, rule := range defaultRules {
		out = rule.pattern.ReplaceAllString(out, "")
	}
	return out
}

func NewFinding(ruleID, severity, locationKind, evidence string) Finding {
	locationKind = normalizeLocationKind(locationKind)
	sum := sha256.Sum256([]byte(ruleID + "\x00" + locationKind + "\x00" + evidence))
	return Finding{
		RuleID:       strings.TrimSpace(ruleID),
		Severity:     strings.TrimSpace(severity),
		LocationKind: locationKind,
		Digest:       hex.EncodeToString(sum[:]),
	}
}

func DedupeFindings(findings []Finding) []Finding {
	seen := map[string]struct{}{}
	out := make([]Finding, 0, len(findings))
	for _, finding := range findings {
		key := finding.RuleID + "\x00" + finding.Severity + "\x00" + finding.LocationKind + "\x00" + finding.Digest
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, finding)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].RuleID != out[j].RuleID {
			return out[i].RuleID < out[j].RuleID
		}
		if out[i].LocationKind != out[j].LocationKind {
			return out[i].LocationKind < out[j].LocationKind
		}
		return out[i].Digest < out[j].Digest
	})
	return out
}

func CorpusSecrets() []string {
	return []string{
		"Authorization: Bearer m13AuthorizationToken123456",
		"Bearer m13BearerToken123456",
		"Cookie: session=m13-cookie-secret",
		"eyJhbGciOiJIUzI1NiJ9.eyJwcm9kY2xhdyI6InRlc3QifQ.m13signature",
		"-----BEGIN PRIVATE KEY-----\nm13-private-key\n-----END PRIVATE KEY-----",
		"AKIA1234567890ABCDEF",
		"ghp_m13githubtokensecret1234567890",
		"glpat-m13gitlabtokensecret",
	}
}

func FindCorpusLeaks(data []byte, locationKind string) []Finding {
	text := string(data)
	var findings []Finding
	for _, secret := range CorpusSecrets() {
		if strings.Contains(text, secret) {
			findings = append(findings, NewFinding("corpus.raw_secret", "critical", locationKind, secret))
		}
	}
	return DedupeFindings(findings)
}

func RedactCorpusText(text string) string {
	out := text
	for _, secret := range CorpusSecrets() {
		out = strings.ReplaceAll(out, secret, "[REDACTED]")
	}
	return out
}

func normalizeLocationKind(locationKind string) string {
	locationKind = strings.TrimSpace(locationKind)
	if locationKind == "" {
		return "unknown"
	}
	return locationKind
}
