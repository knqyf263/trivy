package purl

import (
	"fmt"
	"strconv"
	"strings"

	cn "github.com/google/go-containerregistry/pkg/name"
	version "github.com/knqyf263/go-rpm-version"
	packageurl "github.com/package-url/packageurl-go"
	"golang.org/x/xerrors"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/scanner/utils"
	"github.com/aquasecurity/trivy/pkg/types"
)

const (
	// TypeK8s is a custom type for Kubernetes components in PURL.
	//  - namespace: The service provider such as EKS or GKE. It is not case sensitive and must be lowercased.
	//     Known namespaces:
	//       - empty (upstream)
	//       - eks (AWS)
	//       - aks (GCP)
	//       - gke (Azure)
	//       - rke (Rancher)
	//  - name: The k8s component name and is case sensitive.
	//  - version: The combined version and release of a component.
	//
	//  Examples:
	//    - pkg:k8s/upstream/k8s.io%2Fapiserver@1.24.1
	//    - pkg:k8s/eks/k8s.io%2Fkube-proxy@1.26.2-eksbuild.1
	TypeK8s = "k8s"

	NamespaceEKS = "eks"
	NamespaceAKS = "aks"
	NamespaceGKE = "gke"
	NamespaceRKE = "rke"
	NamespaceOCP = "ocp"

	TypeUnknown = "unknown"
)

type PackageURL struct {
	packageurl.PackageURL
	FilePath string

	original string
}

type Package struct {
	ftypes.Package
	Type            ftypes.PkgType
	Metadata        types.Metadata
	Vulnerabilities []types.DetectedVulnerability
}

func FromString(purl string) (*PackageURL, error) {
	p, err := packageurl.FromString(purl)
	if err != nil {
		return nil, xerrors.Errorf("failed to parse purl(%s): %w", purl, err)
	}

	return &PackageURL{
		PackageURL: p,
		original:   purl,
	}, nil
}

func (p *PackageURL) Package() *Package {
	pkg := &Package{
		Type: ftypes.PkgType(p.Type),
		Package: ftypes.Package{
			Name:    p.Name,
			Version: p.Version,
			Ref:     p.original,
		},
	}

	for _, q := range p.Qualifiers {
		switch q.Key {
		case "arch":
			pkg.Arch = q.Value
		case "modularitylabel":
			pkg.Modularitylabel = q.Value
		case "epoch":
			epoch, err := strconv.Atoi(q.Value)
			if err == nil {
				pkg.Epoch = epoch
			}
		}
	}

	// CocoaPods purl has no namespace, but has subpath
	// https://github.com/package-url/purl-spec/blob/a748c36ad415c8aeffe2b8a4a5d8a50d16d6d85f/PURL-TYPES.rst#cocoapods
	if pkg.Type == ftypes.PkgTypeCocoapods && p.Subpath != "" {
		// CocoaPods uses <moduleName>/<submoduleName> format for package name
		// e.g. `pkg:cocoapods/GoogleUtilities@7.5.2#NSData+zlib` => `GoogleUtilities/NSData+zlib`
		pkg.Name = p.Name + "/" + p.Subpath
	}

	if pkg.Type == ftypes.PkgTypeRPM {
		rpmVer := version.NewVersion(p.Version)
		pkg.Release = rpmVer.Release()
		pkg.Version = rpmVer.Version()
	}

	// Return packages without namespace.
	// OS packages are not supposed to have namespace.
	if p.Namespace == "" || p.Class() == types.ClassOSPkg {
		return pkg
	}

	if pkg.Type == ftypes.PkgTypeMaven {
		// Maven and Gradle packages separate ":"
		// e.g. org.springframework:spring-core
		pkg.Name = p.Namespace + ":" + p.Name
	} else {
		pkg.Name = p.Namespace + "/" + p.Name
	}

	return pkg
}

// LangType returns an application type in Trivy
// nolint: gocyclo
func (p *PackageURL) LangType() ftypes.LangType {
	switch p.Type {
	case packageurl.TypeComposer:
		return ftypes.Composer
	case packageurl.TypeMaven:
		return ftypes.JAR
	case packageurl.TypeGem:
		return ftypes.GemSpec
	case packageurl.TypeConda:
		return ftypes.CondaPkg
	case packageurl.TypePyPi:
		return ftypes.PythonPkg
	case packageurl.TypeGolang:
		return ftypes.GoBinary
	case packageurl.TypeNPM:
		return ftypes.NodePkg
	case packageurl.TypeCargo:
		return ftypes.Cargo
	case packageurl.TypeNuget:
		return ftypes.NuGet
	case packageurl.TypeSwift:
		return ftypes.Swift
	case packageurl.TypeCocoapods:
		return ftypes.Cocoapods
	case packageurl.TypeHex:
		return ftypes.Hex
	case packageurl.TypeConan:
		return ftypes.Conan
	case packageurl.TypePub:
		return ftypes.Pub
	case TypeK8s:
		switch p.Namespace {
		case NamespaceEKS:
			return ftypes.EKS
		case NamespaceGKE:
			return ftypes.GKE
		case NamespaceAKS:
			return ftypes.AKS
		case NamespaceRKE:
			return ftypes.RKE
		case NamespaceOCP:
			return ftypes.OCP
		case "":
			return ftypes.K8sUpstream
		}
		return TypeUnknown
	default:
		return TypeUnknown
	}
}

func (p *PackageURL) Class() types.ResultClass {
	switch p.Type {
	case packageurl.TypeApk, packageurl.TypeDebian, packageurl.TypeRPM:
		// OS packages
		return types.ClassOSPkg
	default:
		if p.LangType() == TypeUnknown {
			return types.ClassUnknown
		}
		// Language-specific packages
		return types.ClassLangPkg
	}
}

func (p *PackageURL) BOMRef() string {
	// 'bom-ref' must be unique within BOM, but PURLs may conflict
	// when the same packages are installed in an artifact.
	// In that case, we prefer to make PURLs unique by adding file paths,
	// rather than using UUIDs, even if it is not PURL technically.
	// ref. https://cyclonedx.org/use-cases/#dependency-graph
	purl := p.PackageURL // so that it will not override the qualifiers below
	if p.FilePath != "" {
		purl.Qualifiers = append(purl.Qualifiers,
			packageurl.Qualifier{
				Key:   "file_path",
				Value: p.FilePath,
			},
		)
	}
	return purl.String()
}

// nolint: gocyclo
func NewPackageURL(metadata types.Metadata, pkg Package) (*PackageURL, error) {
	var qualifiers packageurl.Qualifiers
	if metadata.OS != nil {
		qualifiers = parseQualifier(pkg)
		pkg.Epoch = 0 // we moved Epoch to qualifiers so we don't need it in version
	}

	name := pkg.Name
	ver := utils.FormatVersion(pkg.Package)
	namespace := ""
	subpath := ""

	switch pkg.Type {
	case ftypes.PkgTypeRPM:
		ns, qs := parseRPM(metadata.OS, pkg.Modularitylabel)
		namespace = string(ns)
		qualifiers = append(qualifiers, qs...)
	case ftypes.PkgTypeDeb:
		qualifiers = append(qualifiers, parseDeb(metadata.OS)...)
		if metadata.OS != nil {
			namespace = string(metadata.OS.Family)
		}
	case ftypes.PkgTypeApk:
		var qs packageurl.Qualifiers
		name, namespace, qs = parseApk(name, metadata.OS)
		qualifiers = append(qualifiers, qs...)
	case ftypes.PkgTypeMaven:
		namespace, name = parseMaven(name)
	case ftypes.PkgTypePyPI:
		name = parsePyPI(name)
	case ftypes.PkgTypeComposer:
		namespace, name = parseComposer(name)
	case ftypes.PkgTypeGolang:
		namespace, name = parseGolang(name)
		if name == "" {
			return nil, nil
		}
	case ftypes.PkgTypeNPM:
		namespace, name = parseNpm(name)
	case ftypes.PkgTypeSwift:
		namespace, name = parseSwift(name)
	case ftypes.PkgTypeCocoapods:
		name, subpath = parseCocoapods(name)
	case ftypes.PkgTypeOCI:
		purl, err := parseOCI(metadata)
		if err != nil {
			return nil, err
		}
		if purl.Type == "" {
			return nil, nil
		}
		return &PackageURL{PackageURL: purl}, nil
	}
	// Trivy's package type should be the same as PURL's type
	ptype := string(pkg.Type)

	return &PackageURL{
		PackageURL: *packageurl.NewPackageURL(ptype, namespace, name, ver, qualifiers, subpath),
		FilePath:   pkg.FilePath,
	}, nil
}

// ref. https://github.com/package-url/purl-spec/blob/a748c36ad415c8aeffe2b8a4a5d8a50d16d6d85f/PURL-TYPES.rst#oci
func parseOCI(metadata types.Metadata) (packageurl.PackageURL, error) {
	if len(metadata.RepoDigests) == 0 {
		return *packageurl.NewPackageURL("", "", "", "", nil, ""), nil
	}

	digest, err := cn.NewDigest(metadata.RepoDigests[0])
	if err != nil {
		return packageurl.PackageURL{}, xerrors.Errorf("failed to parse digest: %w", err)
	}

	name := strings.ToLower(digest.RepositoryStr())
	index := strings.LastIndex(name, "/")
	if index != -1 {
		name = name[index+1:]
	}

	var qualifiers packageurl.Qualifiers
	if repoURL := digest.Repository.Name(); repoURL != "" {
		qualifiers = append(qualifiers, packageurl.Qualifier{
			Key:   "repository_url",
			Value: repoURL,
		})
	}
	if arch := metadata.ImageConfig.Architecture; arch != "" {
		qualifiers = append(qualifiers, packageurl.Qualifier{
			Key:   "arch",
			Value: metadata.ImageConfig.Architecture,
		})
	}

	return *packageurl.NewPackageURL(packageurl.TypeOCI, "", name, digest.DigestStr(), qualifiers, ""), nil
}

// ref. https://github.com/package-url/purl-spec/blob/master/PURL-TYPES.rst#apk
func parseApk(pkgName string, fos *ftypes.OS) (string, string, packageurl.Qualifiers) {
	// the name must be lowercase
	pkgName = strings.ToLower(pkgName)

	if fos == nil {
		return pkgName, "", nil
	}

	// the namespace must be lowercase
	ns := strings.ToLower(string(fos.Family))
	qs := packageurl.Qualifiers{
		{
			Key:   "distro",
			Value: fos.Name,
		},
	}

	return pkgName, ns, qs
}

// ref. https://github.com/package-url/purl-spec/blob/a748c36ad415c8aeffe2b8a4a5d8a50d16d6d85f/PURL-TYPES.rst#deb
func parseDeb(fos *ftypes.OS) packageurl.Qualifiers {
	if fos == nil {
		return packageurl.Qualifiers{}
	}

	distro := fmt.Sprintf("%s-%s", fos.Family, fos.Name)
	return packageurl.Qualifiers{
		{
			Key:   "distro",
			Value: distro,
		},
	}
}

// ref. https://github.com/package-url/purl-spec/blob/a748c36ad415c8aeffe2b8a4a5d8a50d16d6d85f/PURL-TYPES.rst#rpm
func parseRPM(fos *ftypes.OS, modularityLabel string) (ftypes.OSType, packageurl.Qualifiers) {
	if fos == nil {
		return "", nil
	}

	// SLES string has whitespace
	family := fos.Family
	if fos.Family == ftypes.SLES {
		family = "sles"
	}

	qualifiers := packageurl.Qualifiers{
		{
			Key:   "distro",
			Value: fmt.Sprintf("%s-%s", family, fos.Name),
		},
	}

	if modularityLabel != "" {
		qualifiers = append(qualifiers, packageurl.Qualifier{
			Key:   "modularitylabel",
			Value: modularityLabel,
		})
	}
	return family, qualifiers
}

// ref. https://github.com/package-url/purl-spec/blob/a748c36ad415c8aeffe2b8a4a5d8a50d16d6d85f/PURL-TYPES.rst#maven
func parseMaven(pkgName string) (string, string) {
	// The group id is the "namespace" and the artifact id is the "name".
	name := strings.ReplaceAll(pkgName, ":", "/")
	return parsePkgName(name)
}

// ref. https://github.com/package-url/purl-spec/blob/a748c36ad415c8aeffe2b8a4a5d8a50d16d6d85f/PURL-TYPES.rst#golang
func parseGolang(pkgName string) (string, string) {
	// The PURL will be skipped when the package name is a local path, since it can't identify a software package.
	if strings.HasPrefix(pkgName, "./") || strings.HasPrefix(pkgName, "../") {
		return "", ""
	}
	name := strings.ToLower(pkgName)
	return parsePkgName(name)
}

// ref. https://github.com/package-url/purl-spec/blob/a748c36ad415c8aeffe2b8a4a5d8a50d16d6d85f/PURL-TYPES.rst#pypi
func parsePyPI(pkgName string) string {
	// PyPi treats - and _ as the same character and is not case-sensitive.
	// Therefore a Pypi package name must be lowercased and underscore "_" replaced with a dash "-".
	return strings.ToLower(strings.ReplaceAll(pkgName, "_", "-"))
}

// ref. https://github.com/package-url/purl-spec/blob/a748c36ad415c8aeffe2b8a4a5d8a50d16d6d85f/PURL-TYPES.rst#composer
func parseComposer(pkgName string) (string, string) {
	return parsePkgName(pkgName)
}

// ref. https://github.com/package-url/purl-spec/blob/a748c36ad415c8aeffe2b8a4a5d8a50d16d6d85f/PURL-TYPES.rst#swift
func parseSwift(pkgName string) (string, string) {
	return parsePkgName(pkgName)
}

// ref. https://github.com/package-url/purl-spec/blob/a748c36ad415c8aeffe2b8a4a5d8a50d16d6d85f/PURL-TYPES.rst#cocoapods
func parseCocoapods(pkgName string) (string, string) {
	var subpath string
	pkgName, subpath, _ = strings.Cut(pkgName, "/")
	return pkgName, subpath
}

// ref. https://github.com/package-url/purl-spec/blob/a748c36ad415c8aeffe2b8a4a5d8a50d16d6d85f/PURL-TYPES.rst#npm
func parseNpm(pkgName string) (string, string) {
	// the name must be lowercased
	name := strings.ToLower(pkgName)
	return parsePkgName(name)
}

func parseQualifier(pkg Package) packageurl.Qualifiers {
	qualifiers := packageurl.Qualifiers{}
	if pkg.Arch != "" {
		qualifiers = append(qualifiers, packageurl.Qualifier{
			Key:   "arch",
			Value: pkg.Arch,
		})
	}
	if pkg.Epoch != 0 {
		qualifiers = append(qualifiers, packageurl.Qualifier{
			Key:   "epoch",
			Value: strconv.Itoa(pkg.Epoch),
		})
	}
	return qualifiers
}

func parsePkgName(name string) (string, string) {
	var namespace string
	index := strings.LastIndex(name, "/")
	if index != -1 {
		namespace = name[:index]
		name = name[index+1:]
	}
	return namespace, name

}
