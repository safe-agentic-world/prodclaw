package identity

type VerifiedIdentity struct {
	Principal          string                    `json:"principal"`
	Agent              string                    `json:"agent"`
	Environment        string                    `json:"environment"`
	CI                 CIIdentity                `json:"ci,omitempty"`
	CredentialExposure CredentialExposureSummary `json:"credential_exposure,omitempty"`
}

type CIIdentity struct {
	Provider      string `json:"provider,omitempty"`
	Repo          string `json:"repo,omitempty"`
	Project       string `json:"project,omitempty"`
	Ref           string `json:"ref,omitempty"`
	Branch        string `json:"branch,omitempty"`
	CommitSHA     string `json:"commit_sha,omitempty"`
	RunID         string `json:"run_id,omitempty"`
	PipelineID    string `json:"pipeline_id,omitempty"`
	WorkflowRunID string `json:"workflow_run_id,omitempty"`
	JobID         string `json:"job_id,omitempty"`
	Actor         string `json:"actor,omitempty"`
	EventType     string `json:"event_type,omitempty"`
	WorkspaceRoot string `json:"workspace_root,omitempty"`
}

type CredentialExposureSummary struct {
	AgentEnvKeys     []string        `json:"agent_env_keys,omitempty"`
	ExecutorOnlyKeys []string        `json:"executor_only_keys,omitempty"`
	ScrubbedKeys     []string        `json:"scrubbed_keys,omitempty"`
	CredentialScopes map[string]bool `json:"credential_scopes,omitempty"`
}

type AuthConfig struct {
	APIKeys           map[string]string
	ServiceSecrets    map[string]string
	AgentSecrets      map[string]string
	Environment       string
	OIDCEnabled       bool
	OIDCIssuer        string
	OIDCAudience      string
	OIDCPublicKeyPath string
	SPIFFEEnabled     bool
	SPIFFETrustDomain string
}
