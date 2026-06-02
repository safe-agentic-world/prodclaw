package main

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const modulePath = "github.com/safe-agentic-world/prodclaw"

type target struct {
	GOOS   string
	GOARCH string
	Format string
}

type provenanceStatement struct {
	Type          string              `json:"_type"`
	PredicateType string              `json:"predicateType"`
	Subject       []provenanceSubject `json:"subject"`
	Predicate     provenancePredicate `json:"predicate"`
}

type provenanceSubject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

type provenancePredicate struct {
	BuildDefinition provenanceBuildDefinition `json:"buildDefinition"`
	RunDetails      provenanceRunDetails      `json:"runDetails"`
}

type provenanceBuildDefinition struct {
	BuildType            string                         `json:"buildType"`
	ExternalParameters   map[string]string              `json:"externalParameters"`
	InternalParameters   map[string]string              `json:"internalParameters"`
	ResolvedDependencies []provenanceResolvedDependency `json:"resolvedDependencies"`
}

type provenanceResolvedDependency struct {
	URI string `json:"uri"`
}

type provenanceRunDetails struct {
	Builder  map[string]string `json:"builder"`
	Metadata map[string]string `json:"metadata"`
}

func main() {
	var mode string
	var version string
	var dist string
	var repository string
	var workflow string
	var runID string
	var goVersion string
	flag.StringVar(&mode, "mode", "build", "mode: build|provenance")
	flag.StringVar(&version, "version", "", "release version such as v0.1.0")
	flag.StringVar(&dist, "dist", "dist", "distribution directory")
	flag.StringVar(&repository, "repository", defaultEnv("GITHUB_REPOSITORY", "safe-agentic-world/prodclaw"), "source repository")
	flag.StringVar(&workflow, "workflow", ".github/workflows/release.yml", "release workflow path")
	flag.StringVar(&runID, "run-id", os.Getenv("GITHUB_RUN_ID"), "GitHub run id")
	flag.StringVar(&goVersion, "go-version", runtimeGoVersion(), "Go version metadata")
	flag.Parse()

	if err := validateVersion(version); err != nil {
		fatal(err)
	}
	switch mode {
	case "build":
		if err := buildArchives(version, dist); err != nil {
			fatal(err)
		}
	case "provenance":
		if err := writeProvenance(version, dist, repository, workflow, runID, goVersion); err != nil {
			fatal(err)
		}
	default:
		fatal(fmt.Errorf("unknown mode %q", mode))
	}
}

func buildArchives(version, dist string) error {
	if err := os.RemoveAll(dist); err != nil {
		return err
	}
	if err := os.MkdirAll(dist, 0o755); err != nil {
		return err
	}
	commit, err := gitOutput("rev-parse", "--short=12", "HEAD")
	if err != nil {
		return err
	}
	buildDate, err := gitOutput("show", "-s", "--format=%cI", "HEAD")
	if err != nil {
		return err
	}
	targets := []target{
		{GOOS: "linux", GOARCH: "amd64", Format: "tar.gz"},
		{GOOS: "linux", GOARCH: "arm64", Format: "tar.gz"},
		{GOOS: "darwin", GOARCH: "amd64", Format: "tar.gz"},
		{GOOS: "darwin", GOARCH: "arm64", Format: "tar.gz"},
		{GOOS: "windows", GOARCH: "amd64", Format: "zip"},
		{GOOS: "windows", GOARCH: "arm64", Format: "zip"},
	}
	var artifacts []string
	for _, target := range targets {
		artifact, err := buildTarget(version, commit, buildDate, dist, target)
		if err != nil {
			return err
		}
		artifacts = append(artifacts, artifact)
	}
	return writeChecksums(dist, artifacts)
}

func buildTarget(version, commit, buildDate, dist string, target target) (string, error) {
	stage, err := os.MkdirTemp("", "prodclaw-release-*")
	if err != nil {
		return "", err
	}
	defer func() { _ = os.RemoveAll(stage) }()

	binary := "prodclaw"
	if target.GOOS == "windows" {
		binary = "prodclaw.exe"
	}
	binaryPath := filepath.Join(stage, binary)
	ldflags := strings.Join([]string{
		"-s",
		"-w",
		"-X", modulePath + "/internal/version.Version=" + version,
		"-X", modulePath + "/internal/version.Commit=" + commit,
		"-X", modulePath + "/internal/version.BuildDate=" + buildDate,
	}, " ")
	cmd := exec.Command("go", "build", "-trimpath", "-buildvcs=false", "-ldflags", ldflags, "-o", binaryPath, "./cmd/prodclaw")
	cmd.Env = append(os.Environ(), "GOOS="+target.GOOS, "GOARCH="+target.GOARCH, "CGO_ENABLED=0")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return "", err
	}

	name := fmt.Sprintf("prodclaw-%s-%s.%s", target.GOOS, target.GOARCH, target.Format)
	out := filepath.Join(dist, name)
	if target.Format == "zip" {
		return name, zipBinary(out, binaryPath, binary)
	}
	return name, targzBinary(out, binaryPath, binary)
}

func targzBinary(out, binaryPath, binary string) error {
	file, err := os.Create(out)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	gz := gzip.NewWriter(file)
	gz.Header.ModTime = time.Unix(0, 0).UTC()
	defer func() { _ = gz.Close() }()
	tw := tar.NewWriter(gz)
	defer func() { _ = tw.Close() }()

	data, err := os.ReadFile(binaryPath)
	if err != nil {
		return err
	}
	header := &tar.Header{
		Name:    binary,
		Mode:    0o755,
		Size:    int64(len(data)),
		ModTime: time.Unix(0, 0).UTC(),
	}
	if err := tw.WriteHeader(header); err != nil {
		return err
	}
	_, err = tw.Write(data)
	return err
}

func zipBinary(out, binaryPath, binary string) error {
	file, err := os.Create(out)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	zw := zip.NewWriter(file)
	defer func() { _ = zw.Close() }()

	header := &zip.FileHeader{Name: binary, Method: zip.Deflate}
	header.SetMode(0o755)
	header.SetModTime(time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC))
	entry, err := zw.CreateHeader(header)
	if err != nil {
		return err
	}
	input, err := os.Open(binaryPath)
	if err != nil {
		return err
	}
	defer func() { _ = input.Close() }()
	_, err = io.Copy(entry, input)
	return err
}

func writeChecksums(dist string, artifacts []string) error {
	sort.Strings(artifacts)
	var lines []string
	for _, artifact := range artifacts {
		sum, err := fileSHA256(filepath.Join(dist, artifact))
		if err != nil {
			return err
		}
		lines = append(lines, fmt.Sprintf("%s  %s\n", sum, artifact))
	}
	return os.WriteFile(filepath.Join(dist, "prodclaw-checksums.txt"), []byte(strings.Join(lines, "")), 0o644)
}

func writeProvenance(version, dist, repository, workflow, runID, goVersion string) error {
	commit, err := gitOutput("rev-parse", "HEAD")
	if err != nil {
		return err
	}
	patterns := []string{
		"prodclaw-*.tar.gz",
		"prodclaw-*.zip",
		"prodclaw-checksums.txt",
		"prodclaw-sbom.spdx.json",
	}
	var subjects []provenanceSubject
	for _, pattern := range patterns {
		matches, err := filepath.Glob(filepath.Join(dist, pattern))
		if err != nil {
			return err
		}
		sort.Strings(matches)
		for _, match := range matches {
			sum, err := fileSHA256(match)
			if err != nil {
				return err
			}
			subjects = append(subjects, provenanceSubject{
				Name:   filepath.Base(match),
				Digest: map[string]string{"sha256": sum},
			})
		}
	}
	if len(subjects) == 0 {
		return fmt.Errorf("no provenance subjects found in %s", dist)
	}
	statement := provenanceStatement{
		Type:          "https://in-toto.io/Statement/v0.1",
		PredicateType: "https://slsa.dev/provenance/v1",
		Subject:       subjects,
		Predicate: provenancePredicate{
			BuildDefinition: provenanceBuildDefinition{
				BuildType:          "https://github.com/safe-agentic-world/prodclaw/.github/workflows/release.yml",
				ExternalParameters: map[string]string{"tag": version},
				InternalParameters: map[string]string{"go_version": goVersion},
				ResolvedDependencies: []provenanceResolvedDependency{
					{URI: "git+https://github.com/" + repository + "@" + commit},
				},
			},
			RunDetails: provenanceRunDetails{
				Builder:  map[string]string{"id": "https://github.com/" + repository + "/" + workflow},
				Metadata: map[string]string{"invocationId": runID, "sourceRepositoryDigest": commit},
			},
		},
	}
	data, err := json.Marshal(statement)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(filepath.Join(dist, "prodclaw-provenance.intoto.jsonl"), data, 0o644)
}

func fileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = file.Close() }()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func gitOutput(args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func validateVersion(version string) error {
	if strings.TrimSpace(version) == "" {
		return fmt.Errorf("--version is required")
	}
	ok, err := regexp.MatchString(`^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$`, version)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("version must look like v0.1.0 or v0.1.0-rc.1")
	}
	return nil
}

func defaultEnv(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func runtimeGoVersion() string {
	out, err := exec.Command("go", "env", "GOVERSION").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
