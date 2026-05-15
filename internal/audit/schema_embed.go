package audit

import (
	_ "embed"

	"github.com/safe-agentic-world/prodclaw/internal/schema"
)

//go:embed schema/audit_event.v1.json
var auditEventV1Schema []byte

func eventSchema() *schema.Schema {
	s, err := schema.ParseSchema(auditEventV1Schema)
	if err != nil {
		panic(err)
	}
	return s
}
