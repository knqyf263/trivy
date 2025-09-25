package compute

import (
	"github.com/aquasecurity/trivy/internal/iac/types"
)

type Network struct {
	Metadata    types.Metadata
	Firewall    *Firewall
	Subnetworks []SubNetwork
}
