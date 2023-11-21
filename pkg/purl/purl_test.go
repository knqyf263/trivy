package purl_test

import (
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/package-url/packageurl-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/purl"
	"github.com/aquasecurity/trivy/pkg/types"
)

func TestNewPackageURL(t *testing.T) {
	testCases := []struct {
		name     string
		pkg      purl.Package
		metadata types.Metadata
		want     *purl.PackageURL
		wantErr  string
	}{
		{
			name: "maven package",
			pkg: purl.Package{
				Type: ftypes.PkgTypeMaven,
				Package: ftypes.Package{
					Name:    "org.springframework:spring-core",
					Version: "5.3.14",
				},
			},
			want: &purl.PackageURL{
				PackageURL: packageurl.PackageURL{
					Type:      packageurl.TypeMaven,
					Namespace: "org.springframework",
					Name:      "spring-core",
					Version:   "5.3.14",
				},
			},
		},
		{
			name: "gradle package",
			pkg: purl.Package{
				Type: ftypes.PkgTypeMaven,
				Package: ftypes.Package{
					Name:    "org.springframework:spring-core",
					Version: "5.3.14",
				},
			},
			want: &purl.PackageURL{
				PackageURL: packageurl.PackageURL{
					Type:      packageurl.TypeMaven,
					Namespace: "org.springframework",
					Name:      "spring-core",
					Version:   "5.3.14",
				},
			},
		},
		{
			name: "yarn package",
			pkg: purl.Package{
				Type: ftypes.PkgTypeNPM,
				Package: ftypes.Package{
					Name:    "@xtuc/ieee754",
					Version: "1.2.0",
				},
			},
			want: &purl.PackageURL{
				PackageURL: packageurl.PackageURL{
					Type:      packageurl.TypeNPM,
					Namespace: "@xtuc",
					Name:      "ieee754",
					Version:   "1.2.0",
				},
			},
		},
		{
			name: "yarn package with non-namespace",
			pkg: purl.Package{
				Type: ftypes.PkgTypeNPM,
				Package: ftypes.Package{
					Name:    "lodash",
					Version: "4.17.21",
				},
			},
			want: &purl.PackageURL{
				PackageURL: packageurl.PackageURL{
					Type:    packageurl.TypeNPM,
					Name:    "lodash",
					Version: "4.17.21",
				},
			},
		},
		{
			name: "pnpm package",
			pkg: purl.Package{
				Type: ftypes.PkgTypeNPM,
				Package: ftypes.Package{
					Name:    "@xtuc/ieee754",
					Version: "1.2.0",
				},
			},
			want: &purl.PackageURL{
				PackageURL: packageurl.PackageURL{
					Type:      packageurl.TypeNPM,
					Namespace: "@xtuc",
					Name:      "ieee754",
					Version:   "1.2.0",
				},
			},
		},
		{
			name: "pnpm package with non-namespace",
			pkg: purl.Package{
				Type: ftypes.PkgTypeNPM,
				Package: ftypes.Package{
					Name:    "lodash",
					Version: "4.17.21",
				},
			},
			want: &purl.PackageURL{
				PackageURL: packageurl.PackageURL{
					Type:    packageurl.TypeNPM,
					Name:    "lodash",
					Version: "4.17.21",
				},
			},
		},
		{
			name: "pypi package",
			pkg: purl.Package{
				Type: ftypes.PkgTypePyPI,
				Package: ftypes.Package{
					Name:    "Django_test",
					Version: "1.2.0",
				},
			},
			want: &purl.PackageURL{
				PackageURL: packageurl.PackageURL{
					Type:    packageurl.TypePyPi,
					Name:    "django-test",
					Version: "1.2.0",
				},
			},
		},
		{
			name: "conda package",
			pkg: purl.Package{
				Type: ftypes.PkgTypeConda,
				Package: ftypes.Package{
					Name:    "absl-py",
					Version: "0.4.1",
				},
			},
			want: &purl.PackageURL{
				PackageURL: packageurl.PackageURL{
					Type:    packageurl.TypeConda,
					Name:    "absl-py",
					Version: "0.4.1",
				},
			},
		},
		{
			name: "composer package",
			pkg: purl.Package{
				Type: ftypes.PkgTypeComposer,
				Package: ftypes.Package{
					Name:    "symfony/contracts",
					Version: "v1.0.2",
				},
			},
			want: &purl.PackageURL{
				PackageURL: packageurl.PackageURL{
					Type:      packageurl.TypeComposer,
					Namespace: "symfony",
					Name:      "contracts",
					Version:   "v1.0.2",
				},
			},
		},
		{
			name: "golang package",
			pkg: purl.Package{
				Type: ftypes.PkgTypeGolang,
				Package: ftypes.Package{
					Name:    "github.com/go-sql-driver/Mysql",
					Version: "v1.5.0",
				},
			},
			want: &purl.PackageURL{
				PackageURL: packageurl.PackageURL{
					Type:      packageurl.TypeGolang,
					Namespace: "github.com/go-sql-driver",
					Name:      "mysql",
					Version:   "v1.5.0",
				},
			},
		},
		{
			name: "golang package with a local path",
			pkg: purl.Package{
				Type: ftypes.PkgTypeGolang,
				Package: ftypes.Package{
					Name:    "./private_repos/cnrm.googlesource.com/cnrm/",
					Version: "(devel)",
				},
			},
			want: nil,
		},
		{
			name: "hex package",
			pkg: purl.Package{
				Type: ftypes.PkgTypeHex,
				Package: ftypes.Package{
					ID:      "bunt@0.2.0",
					Name:    "bunt",
					Version: "0.2.0",
					Locations: []ftypes.Location{
						{
							StartLine: 2,
							EndLine:   2,
						},
					},
				},
			},
			want: &purl.PackageURL{
				PackageURL: packageurl.PackageURL{
					Type:    packageurl.TypeHex,
					Name:    "bunt",
					Version: "0.2.0",
				},
			},
		},
		{
			name: "dart package",
			pkg: purl.Package{
				Type: ftypes.PkgTypePub,
				Package: ftypes.Package{
					Name:    "http",
					Version: "0.13.2",
				},
			},
			want: &purl.PackageURL{
				PackageURL: packageurl.PackageURL{
					Type:    packageurl.TypePub,
					Name:    "http",
					Version: "0.13.2",
				},
			},
		},
		{
			name: "swift package",
			pkg: purl.Package{
				Type: ftypes.PkgTypeSwift,
				Package: ftypes.Package{
					ID:      "github.com/apple/swift-atomics@1.1.0",
					Name:    "github.com/apple/swift-atomics",
					Version: "1.1.0",
				},
			},
			want: &purl.PackageURL{
				PackageURL: packageurl.PackageURL{
					Type:      packageurl.TypeSwift,
					Namespace: "github.com/apple",
					Name:      "swift-atomics",
					Version:   "1.1.0",
				},
			},
		},
		{
			name: "cocoapods package",
			pkg: purl.Package{
				Type: ftypes.PkgTypeCocoapods,
				Package: ftypes.Package{
					ID:      "GoogleUtilities/NSData+zlib@7.5.2",
					Name:    "GoogleUtilities/NSData+zlib",
					Version: "7.5.2",
				},
			},
			want: &purl.PackageURL{
				PackageURL: packageurl.PackageURL{
					Type:    packageurl.TypeCocoapods,
					Name:    "GoogleUtilities",
					Version: "7.5.2",
					Subpath: "NSData+zlib",
				},
			},
		},
		{
			name: "rust binary",
			pkg: purl.Package{
				Type: ftypes.PkgTypeCargo,
				Package: ftypes.Package{
					ID:      "abomination@0.7.3",
					Name:    "abomination",
					Version: "0.7.3",
				},
			},
			want: &purl.PackageURL{
				PackageURL: packageurl.PackageURL{
					Type:    packageurl.TypeCargo,
					Name:    "abomination",
					Version: "0.7.3",
				},
			},
		},
		{
			name: "os package",
			pkg: purl.Package{
				Type: ftypes.PkgTypeRPM,
				Package: ftypes.Package{
					Name:            "acl",
					Version:         "2.2.53",
					Release:         "1.el8",
					Epoch:           1,
					Arch:            "aarch64",
					SrcName:         "acl",
					SrcVersion:      "2.2.53",
					SrcRelease:      "1.el8",
					SrcEpoch:        1,
					Modularitylabel: "",
				},
			},

			metadata: types.Metadata{
				OS: &ftypes.OS{
					Family: ftypes.RedHat,
					Name:   "8",
				},
			},
			want: &purl.PackageURL{
				PackageURL: packageurl.PackageURL{
					Type:      packageurl.TypeRPM,
					Namespace: "redhat",
					Name:      "acl",
					Version:   "2.2.53-1.el8",
					Qualifiers: packageurl.Qualifiers{
						{
							Key:   "arch",
							Value: "aarch64",
						},
						{
							Key:   "epoch",
							Value: "1",
						},
						{
							Key:   "distro",
							Value: "redhat-8",
						},
					},
				},
			},
		},
		{
			name: "container",
			pkg: purl.Package{
				Type: ftypes.PkgTypeOCI,
			},
			metadata: types.Metadata{
				RepoTags: []string{
					"cblmariner2preview.azurecr.io/base/core:2.0.20220124-amd64",
				},
				RepoDigests: []string{
					"cblmariner2preview.azurecr.io/base/core@sha256:8fe1727132b2506c17ba0e1f6a6ed8a016bb1f5735e43b2738cd3fd1979b6260",
					"cblmariner2preview.azurecr.io/base/core@sha256:016bb1f5735e43b2738cd3fd1979b62608fe1727132b2506c17ba0e1f6a6ed8a",
				},
				ImageConfig: v1.ConfigFile{
					Architecture: "amd64",
				},
			},
			want: &purl.PackageURL{
				PackageURL: packageurl.PackageURL{
					Type:      packageurl.TypeOCI,
					Namespace: "",
					Name:      "core",
					Version:   "sha256:8fe1727132b2506c17ba0e1f6a6ed8a016bb1f5735e43b2738cd3fd1979b6260",
					Qualifiers: packageurl.Qualifiers{
						{
							Key:   "repository_url",
							Value: "cblmariner2preview.azurecr.io/base/core",
						},
						{
							Key:   "arch",
							Value: "amd64",
						},
					},
				},
			},
		},
		{
			name: "container local",
			pkg: purl.Package{
				Type: ftypes.PkgTypeOCI,
			},
			metadata: types.Metadata{
				RepoTags:    []string{},
				RepoDigests: []string{},
				ImageConfig: v1.ConfigFile{
					Architecture: "amd64",
				},
				ImageID: "sha256:8fe1727132b2506c17ba0e1f6a6ed8a016bb1f5735e43b2738cd3fd1979b6260",
			},
			want: nil,
		},
		{
			name: "container with implicit registry",
			pkg: purl.Package{
				Type: ftypes.PkgTypeOCI,
			},
			metadata: types.Metadata{
				RepoTags: []string{
					"alpine:3.14",
					"alpine:latest",
				},
				RepoDigests: []string{
					"alpine:3.14@sha256:8fe1727132b2506c17ba0e1f6a6ed8a016bb1f5735e43b2738cd3fd1979b6260",
					"alpine:latest@sha256:016bb1f5735e43b2738cd3fd1979b62608fe1727132b2506c17ba0e1f6a6ed8a",
				},
				ImageConfig: v1.ConfigFile{
					Architecture: "amd64",
				},
			},
			want: &purl.PackageURL{
				PackageURL: packageurl.PackageURL{
					Type:      packageurl.TypeOCI,
					Namespace: "",
					Name:      "alpine",
					Version:   "sha256:8fe1727132b2506c17ba0e1f6a6ed8a016bb1f5735e43b2738cd3fd1979b6260",
					Qualifiers: packageurl.Qualifiers{
						{
							Key:   "repository_url",
							Value: "index.docker.io/library/alpine",
						},
						{
							Key:   "arch",
							Value: "amd64",
						},
					},
				},
			},
		},
		{
			name: "sad path",
			pkg: purl.Package{
				Type: ftypes.PkgTypeOCI,
			},
			metadata: types.Metadata{
				RepoTags: []string{
					"cblmariner2preview.azurecr.io/base/core:2.0.20220124-amd64",
				},
				RepoDigests: []string{
					"sha256:8fe1727132b2506c17ba0e1f6a6ed8a016bb1f5735e43b2738cd3fd1979b6260",
				},
			},
			wantErr: "failed to parse digest",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			packageURL, err := purl.NewPackageURL(tc.metadata, tc.pkg)
			if tc.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tc.want, packageURL, tc.name)
		})
	}
}

func TestFromString(t *testing.T) {
	testCases := []struct {
		name    string
		purl    string
		want    purl.PackageURL
		wantErr string
	}{
		{
			name: "happy path for maven",
			purl: "pkg:maven/org.springframework/spring-core@5.0.4.RELEASE",
			want: purl.PackageURL{
				PackageURL: packageurl.PackageURL{
					Type:       packageurl.TypeMaven,
					Namespace:  "org.springframework",
					Version:    "5.0.4.RELEASE",
					Name:       "spring-core",
					Qualifiers: packageurl.Qualifiers{},
				},
				FilePath: "",
			},
		},
		{
			name: "happy path for npm",
			purl: "pkg:npm/bootstrap@5.0.2?file_path=app%2Fapp%2Fpackage.json",
			want: purl.PackageURL{
				PackageURL: packageurl.PackageURL{
					Type:    packageurl.TypeNPM,
					Name:    "bootstrap",
					Version: "5.0.2",
					Qualifiers: packageurl.Qualifiers{
						{
							Key:   "file_path",
							Value: "app/app/package.json",
						},
					},
				},
			},
		},
		{
			name: "happy path for coocapods",
			purl: "pkg:cocoapods/GoogleUtilities@7.5.2#NSData+zlib",
			want: purl.PackageURL{
				PackageURL: packageurl.PackageURL{
					Type:       packageurl.TypeCocoapods,
					Name:       "GoogleUtilities",
					Version:    "7.5.2",
					Subpath:    "NSData+zlib",
					Qualifiers: packageurl.Qualifiers{},
				},
			},
		},
		{
			name: "happy path for hex",
			purl: "pkg:hex/plug@1.14.0",
			want: purl.PackageURL{
				PackageURL: packageurl.PackageURL{
					Type:       packageurl.TypeHex,
					Name:       "plug",
					Version:    "1.14.0",
					Qualifiers: packageurl.Qualifiers{},
				},
			},
		},
		{
			name: "happy path for Dart (pub)",
			purl: "pkg:pub/http@0.13.2",
			want: purl.PackageURL{
				PackageURL: packageurl.PackageURL{
					Type:       packageurl.TypePub,
					Name:       "http",
					Version:    "0.13.2",
					Qualifiers: packageurl.Qualifiers{},
				},
			},
		},
		{
			name: "happy path for apk",
			purl: "pkg:apk/alpine/alpine-baselayout@3.2.0-r16?distro=3.14.2&epoch=1",
			want: purl.PackageURL{
				PackageURL: packageurl.PackageURL{
					Type:      string(analyzer.TypeApk),
					Namespace: "alpine",
					Name:      "alpine-baselayout",
					Version:   "3.2.0-r16",
					Qualifiers: packageurl.Qualifiers{
						{
							Key:   "distro",
							Value: "3.14.2",
						},
						{
							Key:   "epoch",
							Value: "1",
						},
					},
				},
			},
		},
		{
			name: "happy path for rpm",
			purl: "pkg:rpm/redhat/containers-common@0.1.14",
			want: purl.PackageURL{
				PackageURL: packageurl.PackageURL{
					Type:       packageurl.TypeRPM,
					Namespace:  "redhat",
					Name:       "containers-common",
					Version:    "0.1.14",
					Qualifiers: packageurl.Qualifiers{},
				},
			},
		},
		{
			name: "happy path for conda",
			purl: "pkg:conda/absl-py@0.4.1",
			want: purl.PackageURL{
				PackageURL: packageurl.PackageURL{
					Type:       packageurl.TypeConda,
					Name:       "absl-py",
					Version:    "0.4.1",
					Qualifiers: packageurl.Qualifiers{},
				},
			},
		},
		{
			name: "bad rpm",
			purl: "pkg:rpm/redhat/a--@1.0.0",
			want: purl.PackageURL{
				PackageURL: packageurl.PackageURL{
					Type:       packageurl.TypeRPM,
					Namespace:  "redhat",
					Name:       "a--",
					Version:    "1.0.0",
					Qualifiers: packageurl.Qualifiers{},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			pkg, err := purl.FromString(tc.purl)
			if tc.wantErr != "" {
				assert.ErrorContains(t, err, tc.wantErr)
				return
			}
			assert.NoError(t, err)
			assert.EqualExportedValues(t, tc.want, *pkg, tc.name)
		})
	}
}

func TestPackageURL_Package(t *testing.T) {
	tests := []struct {
		name   string
		pkgURL *purl.PackageURL
		want   *purl.Package
	}{
		{
			name: "rpm + Qualifiers",
			pkgURL: &purl.PackageURL{
				PackageURL: packageurl.PackageURL{
					Type:      packageurl.TypeRPM,
					Namespace: "redhat",
					Name:      "nodejs-full-i18n",
					Version:   "10.21.0-3.module_el8.2.0+391+8da3adc6",
					Qualifiers: packageurl.Qualifiers{
						{
							Key:   "arch",
							Value: "x86_64",
						},
						{
							Key:   "epoch",
							Value: "1",
						},
						{
							Key:   "modularitylabel",
							Value: "nodejs:10:8020020200707141642:6a468ee4",
						},
						{
							Key:   "distro",
							Value: "redhat-8",
						},
					},
				},
			},
			want: &purl.Package{
				Type: ftypes.PkgTypeRPM,
				Package: ftypes.Package{
					Name:            "nodejs-full-i18n",
					Version:         "10.21.0",
					Release:         "3.module_el8.2.0+391+8da3adc6",
					Arch:            "x86_64",
					Epoch:           1,
					Modularitylabel: "nodejs:10:8020020200707141642:6a468ee4",
				},
			},
		},
		{
			name: "composer with namespace",
			pkgURL: &purl.PackageURL{
				PackageURL: packageurl.PackageURL{
					Type:      packageurl.TypeComposer,
					Namespace: "symfony",
					Name:      "contracts",
					Version:   "v1.0.2",
				},
			},
			want: &purl.Package{
				Type: ftypes.PkgTypeComposer,
				Package: ftypes.Package{
					Name:    "symfony/contracts",
					Version: "v1.0.2",
				},
			},
		},
		{
			name: "maven with namespace",
			pkgURL: &purl.PackageURL{
				PackageURL: packageurl.PackageURL{
					Type:       packageurl.TypeMaven,
					Namespace:  "org.springframework",
					Name:       "spring-core",
					Version:    "5.0.4.RELEASE",
					Qualifiers: packageurl.Qualifiers{},
				},
			},
			want: &purl.Package{
				Type: ftypes.PkgTypeMaven,
				Package: ftypes.Package{
					Name:    "org.springframework:spring-core",
					Version: "5.0.4.RELEASE",
				},
			},
		},
		{
			name: "cocoapods with subpath",
			pkgURL: &purl.PackageURL{
				PackageURL: packageurl.PackageURL{
					Type:       packageurl.TypeCocoapods,
					Version:    "4.2.0",
					Name:       "AppCenter",
					Subpath:    "Analytics",
					Qualifiers: packageurl.Qualifiers{},
				},
			},
			want: &purl.Package{
				Type: ftypes.PkgTypeCocoapods,
				Package: ftypes.Package{
					Name:    "AppCenter/Analytics",
					Version: "4.2.0",
				},
			},
		},
		{
			name: "wrong epoch",
			pkgURL: &purl.PackageURL{
				PackageURL: packageurl.PackageURL{
					Type:      packageurl.TypeRPM,
					Namespace: "redhat",
					Name:      "acl",
					Version:   "2.2.53-1.el8",
					Qualifiers: packageurl.Qualifiers{
						{
							Key:   "epoch",
							Value: "wrong",
						},
					},
				},
			},
			want: &purl.Package{
				Type: ftypes.PkgTypeRPM,
				Package: ftypes.Package{
					Name:    "acl",
					Version: "2.2.53",
					Release: "1.el8",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.pkgURL.Package()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestPackageURL_LangType(t *testing.T) {
	tests := []struct {
		name string
		purl packageurl.PackageURL
		want ftypes.LangType
	}{
		{
			name: "maven",
			purl: packageurl.PackageURL{
				Type:      packageurl.TypeMaven,
				Namespace: "org.springframework",
				Name:      "spring-core",
				Version:   "5.0.4.RELEASE",
			},
			want: ftypes.JAR,
		},
		{
			name: "k8s",
			purl: packageurl.PackageURL{
				Type:    purl.TypeK8s,
				Name:    "kubelet",
				Version: "1.21.1",
			},
			want: ftypes.K8sUpstream,
		},
		{
			name: "eks",
			purl: packageurl.PackageURL{
				Type:      purl.TypeK8s,
				Namespace: purl.NamespaceEKS,
				Name:      "kubelet",
				Version:   "1.21.1",
			},
			want: ftypes.EKS,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &purl.PackageURL{PackageURL: tt.purl}
			assert.Equalf(t, tt.want, p.LangType(), "LangType()")
		})
	}
}
