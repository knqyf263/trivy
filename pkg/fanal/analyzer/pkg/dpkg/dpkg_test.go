package dpkg

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/mapfs"
)

func Test_dpkgAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name string
		// testFiles contains path in testdata and path in OS
		// e.g. tar.list => var/lib/dpkg/info/tar.list
		testFiles map[string]string
		want      *analyzer.AnalysisResult
		wantErr   bool
	}{
		{
			name: "valid",
			testFiles: map[string]string{
				"./testdata/dpkg":     "var/lib/dpkg/status",
				"./testdata/tar.list": "var/lib/dpkg/info/tar.list",
			},
			want: &analyzer.AnalysisResult{
				PackageInfos: []types.PackageInfo{
					{
						FilePath: "var/lib/dpkg/status",
						Packages: []types.Package{
							{
								ID:         "adduser@3.116ubuntu1",
								Name:       "adduser",
								Version:    "3.116ubuntu1",
								SrcName:    "adduser",
								SrcVersion: "3.116ubuntu1",
								DependsOn: []string{
									"debconf@1.5.66",
									"passwd@1:4.5-1ubuntu1",
								},
								Maintainer: "Ubuntu Core Developers <ubuntu-devel-discuss@lists.ubuntu.com>",
								Arch:       "all",
							},
							{
								ID:         "debconf@1.5.66",
								Name:       "debconf",
								Version:    "1.5.66",
								SrcName:    "debconf",
								SrcVersion: "1.5.66",
								Maintainer: "Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>",
								Arch:       "all",
							},
							{
								ID:         "passwd@1:4.5-1ubuntu1",
								Name:       "passwd",
								Epoch:      1,
								Version:    "4.5",
								Release:    "1ubuntu1",
								SrcName:    "shadow",
								SrcEpoch:   1,
								SrcVersion: "4.5",
								SrcRelease: "1ubuntu1",
								Maintainer: "Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>",
								Arch:       "amd64",
							},
							{
								ID:         "tar@1.29b-2",
								Name:       "tar",
								Version:    "1.29b",
								Release:    "2",
								SrcName:    "tar",
								SrcVersion: "1.29b",
								SrcRelease: "2",
								Maintainer: "Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>",
								Arch:       "amd64",
								InstalledFiles: []string{
									"/bin/tar",
									"/etc",
									"/usr/lib/mime/packages/tar",
									"/usr/sbin/rmt-tar",
									"/usr/sbin/tarcat",
									"/usr/share/doc/tar/AUTHORS",
									"/usr/share/doc/tar/NEWS.gz",
									"/usr/share/doc/tar/README.Debian",
									"/usr/share/doc/tar/THANKS.gz",
									"/usr/share/doc/tar/changelog.Debian.gz",
									"/usr/share/doc/tar/copyright",
									"/usr/share/man/man1/tar.1.gz",
									"/usr/share/man/man1/tarcat.1.gz",
									"/usr/share/man/man8/rmt-tar.8.gz",
									"/etc/rmt",
								},
							},
						},
					},
				},
				SystemInstalledFiles: []string{
					"/bin/tar",
					"/etc",
					"/usr/lib/mime/packages/tar",
					"/usr/sbin/rmt-tar",
					"/usr/sbin/tarcat",
					"/usr/share/doc/tar/AUTHORS",
					"/usr/share/doc/tar/NEWS.gz",
					"/usr/share/doc/tar/README.Debian",
					"/usr/share/doc/tar/THANKS.gz",
					"/usr/share/doc/tar/changelog.Debian.gz",
					"/usr/share/doc/tar/copyright",
					"/usr/share/man/man1/tar.1.gz",
					"/usr/share/man/man1/tarcat.1.gz",
					"/usr/share/man/man8/rmt-tar.8.gz",
					"/etc/rmt",
				},
			},
		},
		{
			name:      "corrupsed",
			testFiles: map[string]string{"./testdata/corrupsed": "var/lib/dpkg/status"},
			want: &analyzer.AnalysisResult{
				PackageInfos: []types.PackageInfo{
					{
						FilePath: "var/lib/dpkg/status",
						Packages: []types.Package{
							{
								ID:         "libgcc1@1:5.1.1-12ubuntu1",
								Name:       "libgcc1",
								Version:    "5.1.1",
								Epoch:      1,
								Release:    "12ubuntu1",
								SrcName:    "gcc-5",
								SrcVersion: "5.1.1",
								SrcRelease: "12ubuntu1",
								Maintainer: "Ubuntu Core developers <ubuntu-devel-discuss@lists.ubuntu.com>",
								Arch:       "amd64",
							},
							{
								ID:         "libpam-modules-bin@1.1.8-3.1ubuntu3",
								Name:       "libpam-modules-bin",
								Version:    "1.1.8",
								Release:    "3.1ubuntu3",
								SrcName:    "pam",
								SrcVersion: "1.1.8",
								SrcRelease: "3.1ubuntu3",
								Maintainer: "Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>",
								Arch:       "amd64",
							},
							{
								ID:         "libpam-runtime@1.1.8-3.1ubuntu3",
								Name:       "libpam-runtime",
								Version:    "1.1.8",
								Release:    "3.1ubuntu3",
								SrcName:    "pam",
								SrcVersion: "1.1.8",
								SrcRelease: "3.1ubuntu3",
								Maintainer: "Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>",
								Arch:       "all",
							},
							{
								ID:         "makedev@2.3.1-93ubuntu1",
								Name:       "makedev",
								Version:    "2.3.1",
								Release:    "93ubuntu1",
								SrcName:    "makedev",
								SrcVersion: "2.3.1",
								SrcRelease: "93ubuntu1",
								Maintainer: "Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>",
								Arch:       "all",
							},
						},
					},
				},
			},
		},
		{
			name:      "only apt",
			testFiles: map[string]string{"./testdata/dpkg_apt": "var/lib/dpkg/status"},
			want: &analyzer.AnalysisResult{
				PackageInfos: []types.PackageInfo{
					{
						FilePath: "var/lib/dpkg/status",
						Packages: []types.Package{
							{
								ID:         "apt@1.6.3ubuntu0.1",
								Name:       "apt",
								Version:    "1.6.3ubuntu0.1",
								SrcName:    "apt",
								SrcVersion: "1.6.3ubuntu0.1",
								Maintainer: "Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>",
								Arch:       "amd64",
							},
						},
					},
				},
			},
		},
		{
			name: "happy path with digests",
			testFiles: map[string]string{
				"./testdata/digest-status":    "var/lib/dpkg/status",
				"./testdata/digest-available": "var/lib/dpkg/available",
			},
			want: &analyzer.AnalysisResult{
				PackageInfos: []types.PackageInfo{
					{
						FilePath: "var/lib/dpkg/status",
						Packages: []types.Package{
							{
								ID:         "sed@4.4-2",
								Name:       "sed",
								Version:    "4.4",
								Release:    "2",
								SrcName:    "sed",
								SrcVersion: "4.4",
								SrcRelease: "2",
								Maintainer: "Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>",
								Arch:       "amd64",
							},
							{
								ID:         "tar@1.34+dfsg-1",
								Name:       "tar",
								Version:    "1.34+dfsg",
								Release:    "1",
								SrcName:    "tar",
								SrcVersion: "1.34+dfsg",
								SrcRelease: "1",
								Maintainer: "Janos Lenart <ocsi@debian.org>",
								Arch:       "amd64",
								Digest:     "sha256:bd8e963c6edcf1c806df97cd73560794c347aa94b9aaaf3b88eea585bb2d2f3c",
							},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, err := newDpkgAnalyzer(analyzer.AnalyzerOptions{})
			assert.NoError(t, err)
			ctx := context.Background()

			mfs := mapfs.New()
			for testPath, osPath := range tt.testFiles {
				err = mfs.MkdirAll(filepath.Dir(osPath), os.ModePerm)
				assert.NoError(t, err)
				err = mfs.WriteFile(osPath, testPath)
				assert.NoError(t, err)
			}

			got, err := a.PostAnalyze(ctx, analyzer.PostAnalysisInput{
				FS: mfs,
			})
			assert.NoError(t, err)

			// Sort the result for consistency
			for i := range got.PackageInfos {
				sort.Sort(got.PackageInfos[i].Packages)
			}

			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_dpkgAnalyzer_Required(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{
			name:     "status",
			filePath: "var/lib/dpkg/status",
			want:     true,
		},
		{
			name:     "status dir",
			filePath: "var/lib/dpkg/status.d/gcc",
			want:     true,
		},
		{
			name:     "*.md5sums file in status dir",
			filePath: "var/lib/dpkg/status.d/base-files.md5sums",
			want:     false,
		},
		{
			name:     "list file",
			filePath: "var/lib/dpkg/info/bash.list",
			want:     true,
		},
		{
			name:     "available file",
			filePath: "var/lib/dpkg/available",
			want:     true,
		},
		{
			name:     "sad path",
			filePath: "var/lib/dpkg/status/bash.list",
			want:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, err := newDpkgAnalyzer(analyzer.AnalyzerOptions{})
			assert.NoError(t, err)
			got := a.Required(tt.filePath, nil)
			assert.Equal(t, tt.want, got)
		})
	}
}
