package ospkg

import (
	"testing"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

func Test_isUnlikelyAffected(t *testing.T) {
	tests := []struct {
		name string
		pkg  ftypes.Package
		want bool
	}{
		{
			name: "Linux kernel package",
			pkg: ftypes.Package{
				Name:    "linux-headers-generic",
				Version: "5.4.0-74.83",
				SrcName: "linux",
			},
			want: true,
		},
		{
			name: "Regular package",
			pkg: ftypes.Package{
				Name:    "curl",
				Version: "7.68.0-1ubuntu2.6",
				SrcName: "curl",
			},
			want: false,
		},
		{
			name: "Package with no source name",
			pkg: ftypes.Package{
				Name:    "some-package",
				Version: "1.0.0",
				SrcName: "",
			},
			want: false,
		},
		{
			name: "Linux-related but not kernel package",
			pkg: ftypes.Package{
				Name:    "linux-libc-dev",
				Version: "5.4.0-74.83",
				SrcName: "linux",
			},
			want: true,
		},
		{
			name: "BPF tools package from linux source",
			pkg: ftypes.Package{
				Name:    "bpftool",
				Version: "5.4.0-74.83",
				SrcName: "linux",
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isUnlikelyAffected(tt.pkg)
			if got != tt.want {
				t.Errorf("isUnlikelyAffected() = %v, want %v", got, tt.want)
			}
		})
	}
}