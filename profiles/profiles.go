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

func Names() []string {
	names := make([]string, 0, len(knownProfiles))
	for name := range knownProfiles {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func Load(name string) (policy.Bundle, error) {
	normalized := strings.TrimSpace(name)
	fileName, ok := knownProfiles[normalized]
	if !ok {
		return policy.Bundle{}, fmt.Errorf("unknown profile %q: expected %s", name, strings.Join(Names(), ", "))
	}
	data, err := profileFS.ReadFile(fileName)
	if err != nil {
		return policy.Bundle{}, fmt.Errorf("read profile %q: %w", normalized, err)
	}
	return policy.LoadBundleBytes(data, fileName)
}
