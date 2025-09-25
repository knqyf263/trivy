package sslcertificate

import (
	iacTypes "github.com/aquasecurity/trivy/internal/iac/types"
)

type ServerCertificate struct {
	Metadata   iacTypes.Metadata
	Expiration iacTypes.TimeValue
}
