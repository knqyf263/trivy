package nas

import (
	iacTypes "github.com/aquasecurity/trivy/internal/iac/types"
)

type NASInstance struct {
	Metadata  iacTypes.Metadata
	NetworkID iacTypes.StringValue
}
