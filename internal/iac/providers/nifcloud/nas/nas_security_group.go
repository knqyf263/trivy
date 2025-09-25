package nas

import (
	iacTypes "github.com/aquasecurity/trivy/internal/iac/types"
)

type NASSecurityGroup struct {
	Metadata    iacTypes.Metadata
	Description iacTypes.StringValue
	CIDRs       []iacTypes.StringValue
}
