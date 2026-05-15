package profiles

import (
	"embed"
	"fmt"
	"sort"
	"strings"

	"github.com/safe-agentic-world/prodclaw/internal/policy"
)

//go:embed *.yaml
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
	Name    string `json:"name"`
	Hash    string `json:"hash"`
	Summary string `json:"summary"`
	YAML    string `json:"yaml,omitempty"`
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
		out = append(out, Profile{Name: name, Hash: bundle.Hash, Summary: summaries[name]})
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
	return Profile{Name: normalized, Hash: bundle.Hash, Summary: summaries[normalized], YAML: string(data)}, nil
}

func YAML(name string) ([]byte, error) {
	normalized := strings.TrimSpace(name)
	fileName, ok := knownProfiles[normalized]
	if !ok {
		return nil, fmt.Errorf("unknown profile %q: expected %s", name, strings.Join(Names(), ", "))
	}
	data, err := profileFS.ReadFile(fileName)
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
	return policy.LoadBundleBytes(data, knownProfiles[normalized])
}
