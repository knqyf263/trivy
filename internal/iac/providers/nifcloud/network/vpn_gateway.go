package network

import (
	iacTypes "github.com/aquasecurity/trivy/internal/iac/types"
)

type VpnGateway struct {
	Metadata      iacTypes.Metadata
	SecurityGroup iacTypes.StringValue
}
