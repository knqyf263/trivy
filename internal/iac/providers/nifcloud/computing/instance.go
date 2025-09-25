package computing

import (
	iacTypes "github.com/aquasecurity/trivy/internal/iac/types"
)

type Instance struct {
	Metadata          iacTypes.Metadata
	SecurityGroup     iacTypes.StringValue
	NetworkInterfaces []NetworkInterface
}

type NetworkInterface struct {
	Metadata  iacTypes.Metadata
	NetworkID iacTypes.StringValue
}
