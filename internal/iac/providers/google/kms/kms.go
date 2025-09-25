package kms

import (
	iacTypes "github.com/aquasecurity/trivy/internal/iac/types"
)

type KMS struct {
	KeyRings []KeyRing
}

type KeyRing struct {
	Metadata iacTypes.Metadata
	Keys     []Key
}

type Key struct {
	Metadata              iacTypes.Metadata
	RotationPeriodSeconds iacTypes.IntValue
}
