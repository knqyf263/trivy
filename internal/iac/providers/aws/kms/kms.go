package kms

import (
	iacTypes "github.com/aquasecurity/trivy/internal/iac/types"
)

type KMS struct {
	Keys []Key
}

const (
	KeyUsageSignAndVerify = "SIGN_VERIFY"
)

type Key struct {
	Metadata        iacTypes.Metadata
	Usage           iacTypes.StringValue
	RotationEnabled iacTypes.BoolValue
}
