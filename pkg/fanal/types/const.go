package types

type (
	// TargetType represents the type of target
	TargetType string

	// OSType is an alias of TargetType for operating systems
	OSType = TargetType

	// LangType is an alias of TargetType for programming languages
	LangType = TargetType

	// ConfigType is an alias of TargetType for configuration files
	ConfigType = TargetType
)

const (
	ArtifactJSONSchemaVersion = 1
	BlobJSONSchemaVersion     = 2

	SBOM TargetType = "sbom"
)

func (l TargetType) PkgType() PkgType {
	switch l {
	case Alpine, Chainguard, Wolfi:
		return PkgTypeApk
	case Alma, CBLMariner, CentOS, Fedora, OpenSUSE, OpenSUSELeap, OpenSUSETumbleweed,
		Oracle, Photon, RedHat, Rocky, SLES:
		return PkgTypeRPM
	case Debian, Ubuntu:
		return PkgTypeDeb
	case Bundler, GemSpec:
		return PkgTypeGem
	case Cargo, RustBinary:
		return PkgTypeCargo
	case Composer:
		return PkgTypeComposer
	case Npm, Yarn, Pnpm, JavaScript, NodePkg:
		return PkgTypeNPM
	case NuGet, DotNetCore:
		return PkgTypeNuGet
	case Pip, Pipenv, Poetry, PythonPkg:
		return PkgTypePyPI
	case CondaPkg:
		// It should be "conda", but there are no security advisories for conda packages.
		// Therefore, we use "pypi" for now.
		return PkgTypePyPI
	case POM, Gradle, JAR:
		return PkgTypeMaven
	case GoBinary, GoModule:
		return PkgTypeGolang
	case Conan:
		return PkgTypeConan
	case Cocoapods:
		return PkgTypeCocoapods
	case Swift:
		return PkgTypeSwift
	case Pub:
		return PkgTypePub
	case Hex:
		return PkgTypeHex
	case K8sUpstream:
		return PkgTypeK8s
	default:
		return PkgType(l)
	}
}

// Operating systems
const (
	Alma               OSType = "alma"
	Alpine             OSType = "alpine"
	Amazon             OSType = "amazon"
	CBLMariner         OSType = "cbl-mariner"
	CentOS             OSType = "centos"
	Chainguard         OSType = "chainguard"
	Debian             OSType = "debian"
	Fedora             OSType = "fedora"
	OpenSUSE           OSType = "opensuse"
	OpenSUSELeap       OSType = "opensuse.leap"
	OpenSUSETumbleweed OSType = "opensuse.tumbleweed"
	Oracle             OSType = "oracle"
	Photon             OSType = "photon"
	RedHat             OSType = "redhat"
	Rocky              OSType = "rocky"
	SLES               OSType = "suse linux enterprise server"
	Ubuntu             OSType = "ubuntu"
	Wolfi              OSType = "wolfi"
)

// Programming language dependencies
const (
	Bundler    LangType = "bundler"
	GemSpec    LangType = "gemspec"
	Cargo      LangType = "cargo"
	Composer   LangType = "composer"
	Npm        LangType = "npm"
	NuGet      LangType = "nuget"
	DotNetCore LangType = "dotnet-core"
	Pip        LangType = "pip"
	Pipenv     LangType = "pipenv"
	Poetry     LangType = "poetry"
	CondaPkg   LangType = "conda-pkg"
	PythonPkg  LangType = "python-pkg"
	NodePkg    LangType = "node-pkg"
	Yarn       LangType = "yarn"
	Pnpm       LangType = "pnpm"
	JAR        LangType = "jar"
	POM        LangType = "pom"
	Gradle     LangType = "gradle"
	GoBinary   LangType = "gobinary"
	GoModule   LangType = "gomod"
	JavaScript LangType = "javascript" // For Trivy Premium
	RustBinary LangType = "rustbinary"
	Conan      LangType = "conan"
	Cocoapods  LangType = "cocoapods"
	Swift      LangType = "swift"
	Pub        LangType = "pub"
	Hex        LangType = "hex"

	K8sUpstream LangType = "kubernetes"
	EKS         LangType = "eks" // Amazon Elastic Kubernetes Service
	GKE         LangType = "gke" // Google Kubernetes Engine
	AKS         LangType = "aks" // Azure Kubernetes Service
	RKE         LangType = "rke" // Rancher Kubernetes Engine
	OCP         LangType = "ocp" // Red Hat OpenShift Container Platform
)

// Config files
const (
	JSON           ConfigType = "json"
	Dockerfile     ConfigType = "dockerfile"
	Terraform      ConfigType = "terraform"
	TerraformPlan  ConfigType = "terraformplan"
	CloudFormation ConfigType = "cloudformation"
	Kubernetes     ConfigType = "kubernetes"
	Helm           ConfigType = "helm"
	Cloud          ConfigType = "cloud"
	AzureARM       ConfigType = "azure-arm"
)

// Language-specific file names
const (
	NuGetPkgsLock   = "packages.lock.json"
	NuGetPkgsConfig = "packages.config"

	GoMod = "go.mod"
	GoSum = "go.sum"

	MavenPom = "pom.xml"

	NpmPkg     = "package.json"
	NpmPkgLock = "package-lock.json"
	YarnLock   = "yarn.lock"
	PnpmLock   = "pnpm-lock.yaml"

	ComposerLock = "composer.lock"
	ComposerJson = "composer.json"

	PyProject       = "pyproject.toml"
	PipRequirements = "requirements.txt"
	PipfileLock     = "Pipfile.lock"
	PoetryLock      = "poetry.lock"

	GemfileLock = "Gemfile.lock"

	CargoLock = "Cargo.lock"
	CargoToml = "Cargo.toml"

	ConanLock = "conan.lock"

	CocoaPodsLock = "Podfile.lock"
	SwiftResolved = "Package.resolved"

	PubSpecLock = "pubspec.lock"

	MixLock = "mix.lock"
)

// PkgType represents the type of package.
// It basically corresponds to the PURL type.
type PkgType string

// Taken from packageurl-go
// cf. https://github.com/package-url/packageurl-go/blob/fe183c1943ec36f257fae7143e160978217104b6/packageurl.go
const (
	PkgTypeApk PkgType = "apk"
	PkgTypeDeb PkgType = "deb"
	PkgTypeRPM PkgType = "rpm"

	PkgTypeCargo     PkgType = "cargo"
	PkgTypeCocoapods PkgType = "cocoapods"
	PkgTypeComposer  PkgType = "composer"
	PkgTypeConan     PkgType = "conan"
	PkgTypeConda     PkgType = "conda"
	PkgTypeGem       PkgType = "gem"
	PkgTypeGolang    PkgType = "golang"
	PkgTypeHex       PkgType = "hex"
	PkgTypeMaven     PkgType = "maven"
	PkgTypeNPM       PkgType = "npm"
	PkgTypeNuGet     PkgType = "nuget"
	PkgTypePub       PkgType = "pub"
	PkgTypePyPI      PkgType = "pypi"
	PkgTypeSwift     PkgType = "swift"

	PkgTypeBitnami PkgType = "bitnami"
	PkgTypeOCI     PkgType = "oci"

	// Custom
	PkgTypeK8s PkgType = "k8s"
)

var (
	// SupportedPkgTypes is a map of package types that are supported by Trivy.
	SupportedPkgTypes = map[PkgType]struct{}{
		PkgTypeApk: {},
		PkgTypeDeb: {},
		PkgTypeRPM: {},

		PkgTypeCargo:     {},
		PkgTypeCocoapods: {},
		PkgTypeComposer:  {},
		PkgTypeConan:     {},
		PkgTypeConda:     {},
		PkgTypeGem:       {},
		PkgTypeGolang:    {},
		PkgTypeHex:       {},
		PkgTypeMaven:     {},
		PkgTypeNPM:       {},
		PkgTypeNuGet:     {},
		PkgTypePub:       {},
		PkgTypePyPI:      {},
		PkgTypeSwift:     {},

		PkgTypeBitnami: {},
		PkgTypeOCI:     {},

		PkgTypeK8s: {},
	}
)

func (t PkgType) OSPkg() bool {
	return t == PkgTypeApk || t == PkgTypeDeb || t == PkgTypeRPM
}
