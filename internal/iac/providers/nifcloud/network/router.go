package network

import (
	iacTypes "github.com/aquasecurity/trivy/internal/iac/types"
)

type Router struct {
	Metadata          iacTypes.Metadata
	SecurityGroup     iacTypes.StringValue
	NetworkInterfaces []NetworkInterface
}
