package rds

import (
	"github.com/aquasecurity/trivy/internal/iac/types"
)

type Classic struct {
	DBSecurityGroups []DBSecurityGroup
}

type DBSecurityGroup struct {
	Metadata types.Metadata
}
