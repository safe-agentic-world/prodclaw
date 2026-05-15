package policy

import (
	"strings"

	"github.com/safe-agentic-world/prodclaw/internal/normalize"
)

type RiskFlags map[string]bool

func ComputeRiskFlags(action normalize.NormalizedAction) RiskFlags {
	flags := RiskFlags{}
	switch action.ActionType {
	case "process.exec":
		flags["risk.exec"] = true
		if params, ok := decodeExecParams(action.Params); ok {
			addExecRiskFlags(flags, params.Argv)
		}
	case "net.http_request":
		flags["risk.net"] = true
	case "fs.write", "repo.apply_patch":
		flags["risk.write"] = true
	case "secrets.checkout":
		flags["risk.secrets"] = true
	}
	if len(action.Params) >= 32*1024 {
		flags["risk.large_io"] = true
	}
	if action.TraceActionCount >= 100 {
		flags["risk.high_fanout"] = true
	}
	return flags
}

func addExecRiskFlags(flags RiskFlags, argv []string) {
	if len(argv) == 0 {
		return
	}
	command := strings.ToLower(argv[0])
	subcommand := ""
	if len(argv) > 1 {
		subcommand = strings.ToLower(argv[1])
	}
	switch {
	case command == "git" && subcommand == "push":
		flags["risk.exec_push"] = true
	case command == "terraform" && (subcommand == "apply" || subcommand == "destroy"):
		flags["risk.exec_deploy"] = true
		if subcommand == "destroy" {
			flags["risk.exec_destroy"] = true
		}
	case command == "kubectl" && subcommand == "delete":
		flags["risk.exec_delete"] = true
	case command == "cat" && len(argv) > 1 && strings.Contains(strings.ToLower(argv[1]), "credential"):
		flags["risk.exec_credential_read"] = true
	case command == "go" && subcommand == "env":
		flags["risk.exec_credential_read"] = true
	case command == "npm" && (subcommand == "install" || subcommand == "ci"):
		flags["risk.exec_package_install"] = true
	case command == "go" && subcommand == "get":
		flags["risk.exec_package_install"] = true
	case command == "python" && len(argv) >= 4 && strings.ToLower(argv[1]) == "-m" && strings.ToLower(argv[2]) == "pip" && strings.ToLower(argv[3]) == "install":
		flags["risk.exec_package_install"] = true
	}
}
