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
			name: "Linux kernel package (Debian/Ubuntu)",
			pkg: ftypes.Package{
				Name:    "linux-headers-generic",
				Version: "5.4.0-74.83",
				SrcName: "linux",
			},
			want: true,
		},
		{
			name: "Kernel package (Red Hat/CentOS)",
			pkg: ftypes.Package{
				Name:    "kernel-devel",
				Version: "4.18.0-348.el8",
				SrcName: "kernel",
			},
			want: true,
		},
		{
			name: "SUSE kernel package",
			pkg: ftypes.Package{
				Name:    "kernel-default",
				Version: "5.14.21-150400.24.18.1",
				SrcName: "kernel-default",
			},
			want: true,
		},
		{
			name: "Documentation package",
			pkg: ftypes.Package{
				Name:    "curl-doc",
				Version: "7.68.0-1ubuntu2.6",
				SrcName: "curl",
			},
			want: true,
		},
		{
			name: "License package",
			pkg: ftypes.Package{
				Name:    "some-package-license",
				Version: "1.0.0",
				SrcName: "some-package",
			},
			want: true,
		},
		{
			name: "Development package",
			pkg: ftypes.Package{
				Name:    "libssl-dev",
				Version: "1.1.1f-1ubuntu2.8",
				SrcName: "openssl",
			},
			want: true,
		},
		{
			name: "Debug package",
			pkg: ftypes.Package{
				Name:    "libc6-dbg",
				Version: "2.31-0ubuntu9.2",
				SrcName: "glibc",
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

func Test_isKernelPackage(t *testing.T) {
	tests := []struct {
		name string
		pkg  ftypes.Package
		want bool
	}{
		{
			name: "Debian/Ubuntu linux source",
			pkg: ftypes.Package{
				SrcName: "linux",
			},
			want: true,
		},
		{
			name: "Red Hat kernel source",
			pkg: ftypes.Package{
				SrcName: "kernel",
			},
			want: true,
		},
		{
			name: "SUSE kernel-default source",
			pkg: ftypes.Package{
				SrcName: "kernel-default",
			},
			want: true,
		},
		{
			name: "SUSE kernel-source",
			pkg: ftypes.Package{
				SrcName: "kernel-source",
			},
			want: true,
		},
		{
			name: "Regular package",
			pkg: ftypes.Package{
				SrcName: "curl",
			},
			want: false,
		},
		{
			name: "Empty source name",
			pkg: ftypes.Package{
				SrcName: "",
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isKernelPackage(tt.pkg)
			if got != tt.want {
				t.Errorf("isKernelPackage() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_isDocumentationPackage(t *testing.T) {
	tests := []struct {
		name    string
		pkgName string
		want    bool
	}{
		{
			name:    "Documentation package with -doc suffix",
			pkgName: "curl-doc",
			want:    true,
		},
		{
			name:    "Documentation package with -docs suffix",
			pkgName: "nginx-docs",
			want:    true,
		},
		{
			name:    "License package",
			pkgName: "some-package-license",
			want:    true,
		},
		{
			name:    "Development package",
			pkgName: "libssl-dev",
			want:    true,
		},
		{
			name:    "Debug package with -dbg suffix",
			pkgName: "libc6-dbg",
			want:    true,
		},
		{
			name:    "Debug package with -debug suffix",
			pkgName: "python3-debug",
			want:    true,
		},
		{
			name:    "Regular package",
			pkgName: "curl",
			want:    false,
		},
		{
			name:    "Package with similar but different suffix",
			pkgName: "some-package-documentation",
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isDocumentationPackage(tt.pkgName)
			if got != tt.want {
				t.Errorf("isDocumentationPackage() = %v, want %v", got, tt.want)
			}
		})
	}
}