package efs

import (
	iacTypes "github.com/aquasecurity/trivy/internal/iac/types"
)

type EFS struct {
	FileSystems []FileSystem
}

type FileSystem struct {
	Metadata  iacTypes.Metadata
	Encrypted iacTypes.BoolValue
}
