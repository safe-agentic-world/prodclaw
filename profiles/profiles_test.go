package profiles

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestEmbeddedProfilesMatchCanonicalSources(t *testing.T) {
	for _, name := range Names() {
		canonical, err := os.ReadFile(name + ".yaml")
		if err != nil {
			t.Fatalf("read canonical profile %s: %v", name, err)
		}
		embedded, err := profileFS.ReadFile(filepath.ToSlash(filepath.Join("embedded", name+".yaml")))
		if err != nil {
			t.Fatalf("read embedded profile %s: %v", name, err)
		}
		if !bytes.Equal(canonical, embedded) {
			t.Fatalf("embedded profile %s has drifted from canonical source; run `go generate ./profiles`", name)
		}
	}
}

func TestVerifyReportsCanonicalMatchWhenSourcesArePresent(t *testing.T) {
	records := Verify(".")
	if len(records) != len(knownProfiles) {
		t.Fatalf("verify record count = %d, want %d", len(records), len(knownProfiles))
	}
	for _, record := range records {
		if !record.EmbeddedValid || !record.CanonicalPresent || !record.CanonicalMatches || record.Error != "" {
			t.Fatalf("unexpected verify record: %+v", record)
		}
	}
}
