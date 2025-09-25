package compute

import (
	iacTypes "github.com/aquasecurity/trivy/internal/iac/types"
)

type ProjectMetadata struct {
	Metadata      iacTypes.Metadata
	EnableOSLogin iacTypes.BoolValue
}
