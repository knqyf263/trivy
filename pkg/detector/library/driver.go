package library

import (
	"fmt"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/db"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare/maven"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare/npm"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare/pep440"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare/rubygems"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"
)

// NewDriver returns a driver according to the library type
func NewDriver(pkgType ftypes.PkgType) (Driver, bool) {
	var ecosystem dbTypes.Ecosystem
	var comparer compare.Comparer

	switch pkgType {
	case ftypes.PkgTypeGem:
		ecosystem = vulnerability.RubyGems
		comparer = rubygems.Comparer{}
	case ftypes.PkgTypeCargo:
		ecosystem = vulnerability.Cargo
		comparer = compare.GenericComparer{}
	case ftypes.PkgTypeComposer:
		ecosystem = vulnerability.Composer
		comparer = compare.GenericComparer{}
	case ftypes.PkgTypeGolang:
		ecosystem = vulnerability.Go
		comparer = compare.GenericComparer{}
	case ftypes.PkgTypeMaven:
		ecosystem = vulnerability.Maven
		comparer = maven.Comparer{}
	case ftypes.PkgTypeNPM:
		ecosystem = vulnerability.Npm
		comparer = npm.Comparer{}
	case ftypes.PkgTypeNuGet:
		ecosystem = vulnerability.NuGet
		comparer = compare.GenericComparer{}
	case ftypes.PkgTypePyPI:
		ecosystem = vulnerability.Pip
		comparer = pep440.Comparer{}
	case ftypes.PkgTypePub:
		ecosystem = vulnerability.Pub
		comparer = compare.GenericComparer{}
	case ftypes.PkgTypeHex:
		ecosystem = vulnerability.Erlang
		comparer = compare.GenericComparer{}
	case ftypes.PkgTypeConan:
		ecosystem = vulnerability.Conan
		// Only semver can be used for version ranges
		// https://docs.conan.io/en/latest/versioning/version_ranges.html
		comparer = compare.GenericComparer{}
	case ftypes.PkgTypeSwift:
		// Swift uses semver
		// https://www.swift.org/package-manager/#importing-dependencies
		ecosystem = vulnerability.Swift
		comparer = compare.GenericComparer{}
	case ftypes.PkgTypeCocoapods:
		// CocoaPods uses RubyGems version specifiers
		// https://guides.cocoapods.org/making/making-a-cocoapod.html#cocoapods-versioning-specifics
		ecosystem = vulnerability.Cocoapods
		comparer = rubygems.Comparer{}
	case ftypes.PkgTypeConda:
		log.Logger.Warn("Conda package is supported for SBOM, not for vulnerability scanning")
		return Driver{}, false
	case ftypes.PkgTypeBitnami:
		ecosystem = vulnerability.Bitnami
		comparer = compare.GenericComparer{}
	case ftypes.PkgTypeK8s:
		ecosystem = vulnerability.Kubernetes
		comparer = compare.GenericComparer{}
	default:
		log.Logger.Warnf("The %q package type is not supported for vulnerability scanning", pkgType)
		return Driver{}, false
	}
	return Driver{
		ecosystem: ecosystem,
		comparer:  comparer,
		dbc:       db.Config{},
	}, true
}

// Driver represents security advisories for each programming language
type Driver struct {
	ecosystem dbTypes.Ecosystem
	comparer  compare.Comparer
	dbc       db.Config
}

// Type returns the driver ecosystem
func (d *Driver) Type() string {
	return string(d.ecosystem)
}

// DetectVulnerabilities scans buckets with the prefix according to the ecosystem.
// If "ecosystem" is pip, it looks for buckets with "pip::" and gets security advisories from those buckets.
// It allows us to add a new data source with the ecosystem prefix (e.g. pip::new-data-source)
// and detect vulnerabilities without specifying a specific bucket name.
func (d *Driver) DetectVulnerabilities(pkgID, pkgName, pkgVer string) ([]types.DetectedVulnerability, error) {
	// e.g. "pip::", "npm::"
	prefix := fmt.Sprintf("%s::", d.ecosystem)
	advisories, err := d.dbc.GetAdvisories(prefix, vulnerability.NormalizePkgName(d.ecosystem, pkgName))
	if err != nil {
		return nil, xerrors.Errorf("failed to get %s advisories: %w", d.ecosystem, err)
	}

	var vulns []types.DetectedVulnerability
	for _, adv := range advisories {
		if !d.comparer.IsVulnerable(pkgVer, adv) {
			continue
		}

		vuln := types.DetectedVulnerability{
			VulnerabilityID:  adv.VulnerabilityID,
			PkgID:            pkgID,
			PkgName:          pkgName,
			InstalledVersion: pkgVer,
			FixedVersion:     createFixedVersions(adv),
			DataSource:       adv.DataSource,
		}
		vulns = append(vulns, vuln)
	}

	return vulns, nil
}

func createFixedVersions(advisory dbTypes.Advisory) string {
	if len(advisory.PatchedVersions) != 0 {
		return strings.Join(advisory.PatchedVersions, ", ")
	}

	var fixedVersions []string
	for _, version := range advisory.VulnerableVersions {
		for _, s := range strings.Split(version, ",") {
			s = strings.TrimSpace(s)
			if !strings.HasPrefix(s, "<=") && strings.HasPrefix(s, "<") {
				s = strings.TrimPrefix(s, "<")
				fixedVersions = append(fixedVersions, strings.TrimSpace(s))
			}
		}
	}
	return strings.Join(fixedVersions, ", ")
}
