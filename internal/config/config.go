package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

type Values struct {
	PolicyBundle string       `json:"policy_bundle,omitempty"`
	PolicyInputs PolicyInputs `json:"policy_inputs,omitempty"`
	Profile      string       `json:"profile,omitempty"`
	Workspace    string       `json:"workspace,omitempty"`
	AuditPath    string       `json:"audit,omitempty"`
	Principal    string       `json:"principal,omitempty"`
	Agent        string       `json:"agent,omitempty"`
	Environment  string       `json:"environment,omitempty"`
	TaskPath     string       `json:"task,omitempty"`
	TaskFile     string       `json:"task_file,omitempty"`
	TaskText     string       `json:"task_text,omitempty"`
	ControlledCI bool         `json:"controlled_ci,omitempty"`
}

type PolicyInput struct {
	Path   string `json:"path,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
}

type PolicyInputs struct {
	Baseline     PolicyInput `json:"baseline,omitempty"`
	Organization PolicyInput `json:"organization,omitempty"`
	Repository   PolicyInput `json:"repository,omitempty"`
	Environment  PolicyInput `json:"environment,omitempty"`
	Job          PolicyInput `json:"job,omitempty"`
}

type OrderedPolicyInput struct {
	Role   string
	Path   string
	SHA256 string
}

type LookupEnv func(string) (string, bool)

func Load(path string, lookupEnv LookupEnv) (Values, error) {
	var values Values
	if strings.TrimSpace(path) != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return Values{}, fmt.Errorf("read config: %w", err)
		}
		decoded, err := Decode(data)
		if err != nil {
			return Values{}, err
		}
		values = decoded
	}
	if lookupEnv == nil {
		lookupEnv = os.LookupEnv
	}
	values.applyEnv(lookupEnv)
	return values, nil
}

func Decode(data []byte) (Values, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var values Values
	if err := dec.Decode(&values); err != nil {
		return Values{}, fmt.Errorf("decode config: %w", err)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return Values{}, errors.New("config contains trailing data")
	}
	return values, nil
}

func (v *Values) applyEnv(lookupEnv LookupEnv) {
	apply := func(target *string, key string) {
		if value, ok := lookupEnv(key); ok {
			*target = value
		}
	}
	apply(&v.PolicyBundle, "PRODCLAW_POLICY_BUNDLE")
	apply(&v.PolicyInputs.Baseline.Path, "PRODCLAW_POLICY_BASELINE")
	apply(&v.PolicyInputs.Organization.Path, "PRODCLAW_POLICY_ORGANIZATION")
	apply(&v.PolicyInputs.Repository.Path, "PRODCLAW_POLICY_REPOSITORY")
	apply(&v.PolicyInputs.Environment.Path, "PRODCLAW_POLICY_ENVIRONMENT")
	apply(&v.PolicyInputs.Job.Path, "PRODCLAW_POLICY_JOB")
	apply(&v.PolicyInputs.Baseline.SHA256, "PRODCLAW_POLICY_BASELINE_SHA256")
	apply(&v.PolicyInputs.Organization.SHA256, "PRODCLAW_POLICY_ORGANIZATION_SHA256")
	apply(&v.PolicyInputs.Repository.SHA256, "PRODCLAW_POLICY_REPOSITORY_SHA256")
	apply(&v.PolicyInputs.Environment.SHA256, "PRODCLAW_POLICY_ENVIRONMENT_SHA256")
	apply(&v.PolicyInputs.Job.SHA256, "PRODCLAW_POLICY_JOB_SHA256")
	apply(&v.Profile, "PRODCLAW_PROFILE")
	apply(&v.Workspace, "PRODCLAW_WORKSPACE")
	apply(&v.AuditPath, "PRODCLAW_AUDIT")
	apply(&v.Principal, "PRODCLAW_PRINCIPAL")
	apply(&v.Agent, "PRODCLAW_AGENT")
	apply(&v.Environment, "PRODCLAW_ENVIRONMENT")
	if value, ok := lookupEnv("PRODCLAW_TASK"); ok {
		v.TaskPath = value
		v.TaskFile = ""
		v.TaskText = ""
	}
	if value, ok := lookupEnv("PRODCLAW_TASK_FILE"); ok {
		v.TaskPath = ""
		v.TaskFile = value
		v.TaskText = ""
	}
	if value, ok := lookupEnv("PRODCLAW_TASK_TEXT"); ok {
		v.TaskPath = ""
		v.TaskFile = ""
		v.TaskText = value
	}
	if value, ok := lookupEnv("PRODCLAW_CONTROLLED_CI"); ok {
		v.ControlledCI = parseBool(value)
	}
}

func (p PolicyInputs) HasAny() bool {
	for _, input := range p.Ordered() {
		if strings.TrimSpace(input.Path) != "" || strings.TrimSpace(input.SHA256) != "" {
			return true
		}
	}
	return false
}

func (p PolicyInputs) Ordered() []OrderedPolicyInput {
	return []OrderedPolicyInput{
		{Role: "baseline", Path: p.Baseline.Path, SHA256: p.Baseline.SHA256},
		{Role: "organization", Path: p.Organization.Path, SHA256: p.Organization.SHA256},
		{Role: "repository", Path: p.Repository.Path, SHA256: p.Repository.SHA256},
		{Role: "environment", Path: p.Environment.Path, SHA256: p.Environment.SHA256},
		{Role: "job", Path: p.Job.Path, SHA256: p.Job.SHA256},
	}
}

func parseBool(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}
