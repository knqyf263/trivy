package ec2

import (
	iacTypes "github.com/aquasecurity/trivy/internal/iac/types"
)

type Subnet struct {
	Metadata            iacTypes.Metadata
	MapPublicIpOnLaunch iacTypes.BoolValue
}
