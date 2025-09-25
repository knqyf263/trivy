package compute

import (
	iacTypes "github.com/aquasecurity/trivy/internal/iac/types"
)

type SSLPolicy struct {
	Metadata          iacTypes.Metadata
	Name              iacTypes.StringValue
	Profile           iacTypes.StringValue
	MinimumTLSVersion iacTypes.StringValue
}
