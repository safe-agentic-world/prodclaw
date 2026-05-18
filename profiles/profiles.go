package profiles

import (
	"bytes"
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/safe-agentic-world/prodclaw/internal/policy"
)

//go:generate go run ./genembed

//go:embed embedded/*.yaml
var profileFS embed.FS

var knownProfiles = map[string]string{
	"ci-standard": "ci-standard.yaml",
	"ci-strict":   "ci-strict.yaml",
}

var summaries = map[string]string{
	"ci-standard": "standard CI agent policy: denies secrets and protected-branch pushes, allows feature-branch work",
	"ci-strict":   "strict CI policy: denies all git push commands and limits egress",
}

type Profile struct {
	Name          string `json:"name"`
	Source        string `json:"source"`
	Hash          string `json:"hash"`
	Summary       string `json:"summary"`
	CanonicalPath string `json:"canonical_path,omitempty"`
	YAML          string `json:"yaml,omitempty"`
}

type VerifyRecord struct {
	Name             string `json:"name"`
	Source           string `json:"source"`
	EmbeddedHash     string `json:"embedded_hash,omitempty"`
	EmbeddedValid    bool   `json:"embedded_valid"`
	CanonicalPath    string `json:"canonical_path,omitempty"`
	CanonicalPresent bool   `json:"canonical_present"`
	CanonicalHash    string `json:"canonical_hash,omitempty"`
	CanonicalMatches bool   `json:"canonical_matches"`
	Error            string `json:"error,omitempty"`
}

func Names() []string {
	names := make([]string, 0, len(knownProfiles))
	for name := range knownProfiles {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func List() ([]Profile, error) {
	names := Names()
	out := make([]Profile, 0, len(names))
	for _, name := range names {
		bundle, err := Load(name)
		if err != nil {
			return nil, err
		}
		out = append(out, Profile{Name: name, Source: "embedded", Hash: bundle.Hash, Summary: summaries[name], CanonicalPath: canonicalPath(name)})
	}
	return out, nil
}

func Show(name string) (Profile, error) {
	data, err := YAML(name)
	if err != nil {
		return Profile{}, err
	}
	bundle, err := Load(name)
	if err != nil {
		return Profile{}, err
	}
	normalized := strings.TrimSpace(name)
	return Profile{Name: normalized, Source: "embedded", Hash: bundle.Hash, Summary: summaries[normalized], CanonicalPath: canonicalPath(normalized), YAML: string(data)}, nil
}

func YAML(name string) ([]byte, error) {
	normalized := strings.TrimSpace(name)
	fileName, ok := knownProfiles[normalized]
	if !ok {
		return nil, fmt.Errorf("unknown profile %q: expected %s", name, strings.Join(Names(), ", "))
	}
	data, err := profileFS.ReadFile(filepath.ToSlash(filepath.Join("embedded", fileName)))
	if err != nil {
		return nil, fmt.Errorf("read profile %q: %w", normalized, err)
	}
	return append([]byte(nil), data...), nil
}

func Load(name string) (policy.Bundle, error) {
	normalized := strings.TrimSpace(name)
	data, err := YAML(normalized)
	if err != nil {
		return policy.Bundle{}, err
	}
	bundle, err := policy.LoadBundleBytes(data, knownProfiles[normalized])
	if err != nil {
		return policy.Bundle{}, err
	}
	for idx := range bundle.Rules {
		bundle.Rules[idx].SourcePath = "profile://" + normalized
		bundle.Rules[idx].SourceHash = bundle.Hash
	}
	bundle.SourceBundles = []policy.BundleSource{{Path: "profile://" + normalized, Hash: bundle.Hash, Role: "profile"}}
	return bundle, nil
}

func Verify(sourceDir string) []VerifyRecord {
	if strings.TrimSpace(sourceDir) == "" {
		sourceDir = "profiles"
	}
	records := make([]VerifyRecord, 0, len(knownProfiles))
	for _, name := range Names() {
		record := VerifyRecord{Name: name, Source: "embedded", CanonicalPath: filepath.Join(sourceDir, name+".yaml")}
		embeddedBytes, err := YAML(name)
		if err != nil {
			record.Error = err.Error()
			records = append(records, record)
			continue
		}
		embedded, err := Load(name)
		if err != nil {
			record.Error = err.Error()
			records = append(records, record)
			continue
		}
		record.EmbeddedHash = embedded.Hash
		record.EmbeddedValid = true

		canonicalBytes, err := os.ReadFile(record.CanonicalPath)
		switch {
		case err == nil:
			record.CanonicalPresent = true
			canonical, loadErr := policy.LoadBundleBytes(canonicalBytes, record.CanonicalPath)
			if loadErr != nil {
				record.Error = loadErr.Error()
				break
			}
			record.CanonicalHash = canonical.Hash
			record.CanonicalMatches = bytes.Equal(canonicalBytes, embeddedBytes) && canonical.Hash == embedded.Hash
		case os.IsNotExist(err):
			record.CanonicalPresent = false
		default:
			record.Error = err.Error()
		}
		records = append(records, record)
	}
	return records
}

func canonicalPath(name string) string {
	return filepath.ToSlash(filepath.Join("profiles", strings.TrimSpace(name)+".yaml"))
}
