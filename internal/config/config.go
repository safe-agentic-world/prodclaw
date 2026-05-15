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
	PolicyBundle string `json:"policy_bundle,omitempty"`
	Profile      string `json:"profile,omitempty"`
	Workspace    string `json:"workspace,omitempty"`
	AuditPath    string `json:"audit,omitempty"`
	Principal    string `json:"principal,omitempty"`
	Agent        string `json:"agent,omitempty"`
	Environment  string `json:"environment,omitempty"`
	TaskPath     string `json:"task,omitempty"`
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
	apply(&v.Profile, "PRODCLAW_PROFILE")
	apply(&v.Workspace, "PRODCLAW_WORKSPACE")
	apply(&v.AuditPath, "PRODCLAW_AUDIT")
	apply(&v.Principal, "PRODCLAW_PRINCIPAL")
	apply(&v.Agent, "PRODCLAW_AGENT")
	apply(&v.Environment, "PRODCLAW_ENVIRONMENT")
	apply(&v.TaskPath, "PRODCLAW_TASK")
}
