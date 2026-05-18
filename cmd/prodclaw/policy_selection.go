package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"strings"

	runtimeconfig "github.com/safe-agentic-world/prodclaw/internal/config"
	"github.com/safe-agentic-world/prodclaw/internal/policy"
	"github.com/safe-agentic-world/prodclaw/profiles"
)

type policyLoadRequest struct {
	BundlePath   string
	ProfileName  string
	PolicyInputs runtimeconfig.PolicyInputs
}

type loadedPolicy struct {
	Bundle      policy.Bundle
	Source      string
	ProfileName string
	BundlePath  string
}

type policyInputFlagValues struct {
	BaselinePath     string
	OrganizationPath string
	RepositoryPath   string
	EnvironmentPath  string
	JobPath          string
	BaselineHash     string
	OrganizationHash string
	RepositoryHash   string
	EnvironmentHash  string
	JobHash          string
}

func bindPolicyInputFlags(fs *flag.FlagSet, values *policyInputFlagValues) {
	fs.StringVar(&values.BaselinePath, "policy-baseline", "", "baseline policy bundle path")
	fs.StringVar(&values.OrganizationPath, "policy-organization", "", "organization policy bundle path")
	fs.StringVar(&values.RepositoryPath, "policy-repository", "", "repository policy bundle path")
	fs.StringVar(&values.EnvironmentPath, "policy-environment", "", "environment policy bundle path")
	fs.StringVar(&values.JobPath, "policy-job", "", "job-specific policy bundle path")
	fs.StringVar(&values.BaselineHash, "policy-baseline-sha256", "", "expected sha256 for baseline bundle")
	fs.StringVar(&values.OrganizationHash, "policy-organization-sha256", "", "expected sha256 for organization bundle")
	fs.StringVar(&values.RepositoryHash, "policy-repository-sha256", "", "expected sha256 for repository bundle")
	fs.StringVar(&values.EnvironmentHash, "policy-environment-sha256", "", "expected sha256 for environment bundle")
	fs.StringVar(&values.JobHash, "policy-job-sha256", "", "expected sha256 for job-specific bundle")
}

func overlayPolicyInputFlags(fs *flag.FlagSet, cfg *runtimeconfig.PolicyInputs, values policyInputFlagValues) {
	apply := func(flagName string, target *string, value string) {
		if flagWasSet(fs, flagName) {
			*target = value
		}
	}
	apply("policy-baseline", &cfg.Baseline.Path, values.BaselinePath)
	apply("policy-organization", &cfg.Organization.Path, values.OrganizationPath)
	apply("policy-repository", &cfg.Repository.Path, values.RepositoryPath)
	apply("policy-environment", &cfg.Environment.Path, values.EnvironmentPath)
	apply("policy-job", &cfg.Job.Path, values.JobPath)
	apply("policy-baseline-sha256", &cfg.Baseline.SHA256, values.BaselineHash)
	apply("policy-organization-sha256", &cfg.Organization.SHA256, values.OrganizationHash)
	apply("policy-repository-sha256", &cfg.Repository.SHA256, values.RepositoryHash)
	apply("policy-environment-sha256", &cfg.Environment.SHA256, values.EnvironmentHash)
	apply("policy-job-sha256", &cfg.Job.SHA256, values.JobHash)
}

func loadSelectedPolicy(req policyLoadRequest) (loadedPolicy, error) {
	profileName := strings.TrimSpace(req.ProfileName)
	bundlePath := strings.TrimSpace(req.BundlePath)
	hasLayers := req.PolicyInputs.HasAny()
	selected := 0
	if profileName != "" {
		selected++
	}
	if bundlePath != "" {
		selected++
	}
	if hasLayers {
		selected++
	}
	switch {
	case selected == 0:
		return loadedPolicy{}, fmt.Errorf("--bundle, --profile, or layered policy inputs are required")
	case selected > 1:
		return loadedPolicy{}, fmt.Errorf("--bundle, --profile, and layered policy inputs are mutually exclusive")
	case profileName != "":
		bundle, err := profiles.Load(profileName)
		if err != nil {
			return loadedPolicy{}, err
		}
		return loadedPolicy{Bundle: bundle, Source: "embedded_profile", ProfileName: profileName}, nil
	case bundlePath != "":
		bundle, err := policy.LoadBundles([]string{bundlePath})
		if err != nil {
			return loadedPolicy{}, err
		}
		return loadedPolicy{Bundle: bundle, Source: "customer_bundle", BundlePath: bundlePath}, nil
	default:
		bundle, err := loadLayeredPolicy(req.PolicyInputs)
		if err != nil {
			return loadedPolicy{}, err
		}
		return loadedPolicy{Bundle: bundle, Source: "layered_bundles"}, nil
	}
}

func loadLayeredPolicy(inputs runtimeconfig.PolicyInputs) (policy.Bundle, error) {
	ordered := inputs.Ordered()
	paths := make([]string, 0, len(ordered))
	roles := make([]string, 0, len(ordered))
	expectedHashes := make([]string, 0, len(ordered))
	for _, input := range ordered {
		path := strings.TrimSpace(input.Path)
		expectedHash := strings.ToLower(strings.TrimSpace(input.SHA256))
		if path == "" {
			if expectedHash != "" {
				return policy.Bundle{}, fmt.Errorf("policy input %s declares sha256 without a path", input.Role)
			}
			continue
		}
		if expectedHash != "" && !validSHA256(expectedHash) {
			return policy.Bundle{}, fmt.Errorf("policy input %s has invalid sha256", input.Role)
		}
		paths = append(paths, path)
		roles = append(roles, input.Role)
		expectedHashes = append(expectedHashes, expectedHash)
	}
	if len(paths) == 0 {
		return policy.Bundle{}, fmt.Errorf("at least one layered policy input path is required")
	}
	bundle, err := policy.LoadBundlesWithOptions(paths, policy.MultiLoadOptions{BundleRoles: roles})
	if err != nil {
		return policy.Bundle{}, err
	}
	for idx, expectedHash := range expectedHashes {
		if expectedHash == "" {
			continue
		}
		if idx >= len(bundle.SourceBundles) || bundle.SourceBundles[idx].Hash != expectedHash {
			return policy.Bundle{}, fmt.Errorf("policy input %s hash mismatch", roles[idx])
		}
	}
	return bundle, nil
}

func validSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
