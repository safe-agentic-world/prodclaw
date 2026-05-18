package main

import (
	"fmt"
	"os"
	"path/filepath"
)

var profileNames = []string{"ci-standard", "ci-strict"}

func main() {
	const outputDir = "embedded"
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		fatalf("create embedded profile directory: %v", err)
	}
	for _, name := range profileNames {
		source := name + ".yaml"
		target := filepath.Join(outputDir, source)
		data, err := os.ReadFile(source)
		if err != nil {
			fatalf("read %s: %v", source, err)
		}
		if err := os.WriteFile(target, data, 0o644); err != nil {
			fatalf("write %s: %v", target, err)
		}
	}
}

func fatalf(format string, args ...any) {
	_, _ = fmt.Fprintf(os.Stderr, "genembed: "+format+"\n", args...)
	os.Exit(1)
}
