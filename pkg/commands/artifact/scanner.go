package artifact

import (
	"context"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy/pkg/cache"
	"github.com/aquasecurity/trivy/pkg/fanal/applier"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	artimage "github.com/aquasecurity/trivy/pkg/fanal/artifact/image"
	artlocal "github.com/aquasecurity/trivy/pkg/fanal/artifact/local"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact/repo"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact/sbom"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact/vm"
	"github.com/aquasecurity/trivy/pkg/fanal/image"
	"github.com/aquasecurity/trivy/pkg/fanal/walker"
	"github.com/aquasecurity/trivy/pkg/rpc/client"
	"github.com/aquasecurity/trivy/pkg/scan"
	"github.com/aquasecurity/trivy/pkg/scan/langpkg"
	"github.com/aquasecurity/trivy/pkg/scan/local"
	"github.com/aquasecurity/trivy/pkg/scan/ospkg"
	"github.com/aquasecurity/trivy/pkg/vulnerability"
)

// newArtifactFunc is a function that creates an artifact with its cleanup function.
// It takes an artifact cache (either local or remote) and returns the artifact, cleanup function, and any error.
type newArtifactFunc func(cache.ArtifactCache) (artifact.Artifact, func(), error)

////////////////////////////////////////
// Standalone Mode Scanner Functions  //
////////////////////////////////////////

// imageStandaloneScanService scans container images from registries
// Target: Container image (e.g., alpine:3.15, gcr.io/project/image:tag)
// Mode: Standalone (local scanning without server)
func imageStandaloneScanService(ctx context.Context, conf ScannerConfig) (scan.Service, func(), error) {
	return createLocalService(conf, func(c cache.ArtifactCache) (artifact.Artifact, func(), error) {
		img, cleanupImage, err := image.NewContainerImage(ctx, conf.Target, conf.ArtifactOption.ImageOption)
		if err != nil {
			return nil, nil, xerrors.Errorf("unable to initialize container image: %w", err)
		}

		art, err := artimage.NewArtifact(img, c, conf.ArtifactOption)
		if err != nil {
			cleanupImage()
			return nil, nil, xerrors.Errorf("unable to initialize artifact: %w", err)
		}
		return art, cleanupImage, nil
	})
}

// archiveStandaloneScanService scans container image archives
// Target: Image archive file (e.g., alpine.tar created by 'docker save')
// Mode: Standalone (local scanning without server)
func archiveStandaloneScanService(_ context.Context, conf ScannerConfig) (scan.Service, func(), error) {
	return createLocalService(conf, func(c cache.ArtifactCache) (artifact.Artifact, func(), error) {
		img, err := image.NewArchiveImage(conf.Target)
		if err != nil {
			return nil, nil, xerrors.Errorf("unable to initialize archive image: %w", err)
		}

		art, err := artimage.NewArtifact(img, c, conf.ArtifactOption)
		if err != nil {
			return nil, nil, xerrors.Errorf("unable to initialize artifact: %w", err)
		}
		return art, func() {}, nil
	})
}

// filesystemStandaloneScanService scans local filesystems and directories
// Target: Local directory or file path (e.g., /path/to/project, .)
// Mode: Standalone (local scanning without server)
func filesystemStandaloneScanService(_ context.Context, conf ScannerConfig) (scan.Service, func(), error) {
	return createLocalService(conf, func(c cache.ArtifactCache) (artifact.Artifact, func(), error) {
		fs := walker.NewFS()
		art, err := artlocal.NewArtifact(conf.Target, c, fs, conf.ArtifactOption)
		if err != nil {
			return nil, nil, xerrors.Errorf("unable to initialize filesystem artifact: %w", err)
		}
		return art, func() {}, nil
	})
}

// repositoryStandaloneScanService scans git repositories
// Target: Git repository URL or local path (e.g., https://github.com/example/repo, .)
// Mode: Standalone (local scanning without server)
func repositoryStandaloneScanService(_ context.Context, conf ScannerConfig) (scan.Service, func(), error) {
	return createLocalService(conf, func(c cache.ArtifactCache) (artifact.Artifact, func(), error) {
		fs := walker.NewFS()
		art, err := artrepo.NewArtifact(conf.Target, c, fs, conf.ArtifactOption)
		if err != nil {
			return nil, nil, xerrors.Errorf("unable to initialize repository artifact: %w", err)
		}
		return art, func() {}, nil
	})
}

// sbomStandaloneScanService scans SBOM files
// Target: SBOM file path (e.g., sbom.json, sbom.spdx, bom.xml)
// Mode: Standalone (local scanning without server)
func sbomStandaloneScanService(_ context.Context, conf ScannerConfig) (scan.Service, func(), error) {
	return createLocalService(conf, func(c cache.ArtifactCache) (artifact.Artifact, func(), error) {
		art, err := artsbom.NewArtifact(conf.Target, c, conf.ArtifactOption)
		if err != nil {
			return nil, nil, xerrors.Errorf("unable to initialize SBOM artifact: %w", err)
		}
		return art, func() {}, nil
	})
}

// vmStandaloneScanService scans virtual machine images
// Target: VM image file or AMI ID (e.g., disk.vmdk, ami-1234567890abcdef0)
// Mode: Standalone (local scanning without server)
func vmStandaloneScanService(_ context.Context, conf ScannerConfig) (scan.Service, func(), error) {
	return createLocalService(conf, func(c cache.ArtifactCache) (artifact.Artifact, func(), error) {
		vm, err := image.NewVM(conf.Target, conf.ArtifactOption.ImageOption)
		if err != nil {
			return nil, nil, xerrors.Errorf("unable to initialize vm image: %w", err)
		}

		art, err := artimage.NewArtifact(vm, c, conf.ArtifactOption)
		if err != nil {
			return nil, nil, xerrors.Errorf("unable to initialize artifact: %w", err)
		}
		return art, func() {}, nil
	})
}

//////////////////////////////////////////
// Client/Server Mode Scanner Functions //
//////////////////////////////////////////

// imageRemoteScanService scans container images via Trivy server
// Target: Container image (e.g., alpine:3.15, gcr.io/project/image:tag)
// Mode: Client/Server (sends image data to Trivy server for scanning)
func imageRemoteScanService(ctx context.Context, conf ScannerConfig) (scan.Service, func(), error) {
	// Set up remote scanner options
	remoteOptions := client.ScannerOption{
		RemoteURL:     conf.ServerOption.ServerAddr,
		ArtifactType:  types.ArtifactContainerImage,
		RemoteHeaders: conf.ServerOption.CustomHeaders,
		Insecure:      conf.ServerOption.Insecure,
	}

	if conf.ServerOption.ServerAddr == "" {
		return scan.Service{}, func() {}, xerrors.New("remote server address is required")
	}

	remoteScanner := client.NewScanner(remoteOptions, conf.RemoteCacheOptions, types.RemoteOptions{
		Token:  conf.ServerOption.Token,
		Header: conf.ServerOption.TokenHeader,
	})

	// Set the target name for the artifact
	art := remoteArtifact(conf.Target, remoteScanner)
	return scan.NewRemoteService(art, remoteScanner), func() {}, nil
}

// archiveRemoteScanService scans container image archives via Trivy server
// Target: Image archive file (e.g., alpine.tar created by 'docker save')
// Mode: Client/Server (sends archive to Trivy server for scanning)
func archiveRemoteScanService(ctx context.Context, conf ScannerConfig) (scan.Service, func(), error) {
	// Set up remote scanner options
	remoteOptions := client.ScannerOption{
		RemoteURL:     conf.ServerOption.ServerAddr,
		ArtifactType:  types.ArtifactContainerImage, // Note: Archives are scanned as container images remotely
		RemoteHeaders: conf.ServerOption.CustomHeaders,
		Insecure:      conf.ServerOption.Insecure,
	}

	if conf.ServerOption.ServerAddr == "" {
		return scan.Service{}, func() {}, xerrors.New("remote server address is required")
	}

	remoteScanner := client.NewScanner(remoteOptions, conf.RemoteCacheOptions, types.RemoteOptions{
		Token:  conf.ServerOption.Token,
		Header: conf.ServerOption.TokenHeader,
	})

	art := remoteArchiveArtifact(conf.Target, remoteScanner)
	return scan.NewRemoteService(art, remoteScanner), func() {}, nil
}

// filesystemRemoteScanService scans filesystems via Trivy server
// Target: Local directory or file path (e.g., /path/to/project, .)
// Mode: Client/Server (sends filesystem data to Trivy server for scanning)
func filesystemRemoteScanService(ctx context.Context, conf ScannerConfig) (scan.Service, func(), error) {
	// Set up remote scanner options for filesystem
	remoteOptions := client.ScannerOption{
		RemoteURL:     conf.ServerOption.ServerAddr,
		ArtifactType:  types.ArtifactFilesystem,
		RemoteHeaders: conf.ServerOption.CustomHeaders,
		Insecure:      conf.ServerOption.Insecure,
	}

	if conf.ServerOption.ServerAddr == "" {
		return scan.Service{}, func() {}, xerrors.New("remote server address is required")
	}

	remoteScanner := client.NewScanner(remoteOptions, conf.RemoteCacheOptions, types.RemoteOptions{
		Token:  conf.ServerOption.Token,
		Header: conf.ServerOption.TokenHeader,
	})

	art := remoteFilesystemArtifact(conf.Target, remoteScanner)
	return scan.NewRemoteService(art, remoteScanner), func() {}, nil
}

// repositoryRemoteScanService scans git repositories via Trivy server
// Target: Git repository URL or local path (e.g., https://github.com/example/repo, .)
// Mode: Client/Server (sends repository data to Trivy server for scanning)
func repositoryRemoteScanService(ctx context.Context, conf ScannerConfig) (scan.Service, func(), error) {
	// Set up remote scanner options for repository
	remoteOptions := client.ScannerOption{
		RemoteURL:     conf.ServerOption.ServerAddr,
		ArtifactType:  types.ArtifactRepository,
		RemoteHeaders: conf.ServerOption.CustomHeaders,
		Insecure:      conf.ServerOption.Insecure,
	}

	if conf.ServerOption.ServerAddr == "" {
		return scan.Service{}, func() {}, xerrors.New("remote server address is required")
	}

	remoteScanner := client.NewScanner(remoteOptions, conf.RemoteCacheOptions, types.RemoteOptions{
		Token:  conf.ServerOption.Token,
		Header: conf.ServerOption.TokenHeader,
	})

	art := remoteRepositoryArtifact(conf.Target, remoteScanner)
	return scan.NewRemoteService(art, remoteScanner), func() {}, nil
}

// sbomRemoteScanService scans SBOM files via Trivy server
// Target: SBOM file path (e.g., sbom.json, sbom.spdx, bom.xml)
// Mode: Client/Server (sends SBOM to Trivy server for scanning)
func sbomRemoteScanService(ctx context.Context, conf ScannerConfig) (scan.Service, func(), error) {
	// Set up remote scanner options for SBOM
	remoteOptions := client.ScannerOption{
		RemoteURL:     conf.ServerOption.ServerAddr,
		ArtifactType:  types.ArtifactCycloneDX, // SBOMs are typically CycloneDX
		RemoteHeaders: conf.ServerOption.CustomHeaders,
		Insecure:      conf.ServerOption.Insecure,
	}

	if conf.ServerOption.ServerAddr == "" {
		return scan.Service{}, func() {}, xerrors.New("remote server address is required")
	}

	remoteScanner := client.NewScanner(remoteOptions, conf.RemoteCacheOptions, types.RemoteOptions{
		Token:  conf.ServerOption.Token,
		Header: conf.ServerOption.TokenHeader,
	})

	art := remoteSBOMArtifact(conf.Target, remoteScanner)
	return scan.NewRemoteService(art, remoteScanner), func() {}, nil
}

// vmRemoteScanService scans virtual machine images via Trivy server
// Target: VM image file or AMI ID (e.g., disk.vmdk, ami-1234567890abcdef0)
// Mode: Client/Server (sends VM image data to Trivy server for scanning)
func vmRemoteScanService(ctx context.Context, conf ScannerConfig) (scan.Service, func(), error) {
	// Set up remote scanner options for VM
	remoteOptions := client.ScannerOption{
		RemoteURL:     conf.ServerOption.ServerAddr,
		ArtifactType:  types.ArtifactVM,
		RemoteHeaders: conf.ServerOption.CustomHeaders,
		Insecure:      conf.ServerOption.Insecure,
	}

	if conf.ServerOption.ServerAddr == "" {
		return scan.Service{}, func() {}, xerrors.New("remote server address is required")
	}

	remoteScanner := client.NewScanner(remoteOptions, conf.RemoteCacheOptions, types.RemoteOptions{
		Token:  conf.ServerOption.Token,
		Header: conf.ServerOption.TokenHeader,
	})

	art := remoteVMArtifact(conf.Target, remoteScanner)
	return scan.NewRemoteService(art, remoteScanner), func() {}, nil
}

// createLocalService creates a local scanning service using manual dependency injection.
// This replaces the previous Wire-based code generation with explicit dependency management.
//
// Dependency injection process:
// 1. Initialize cache (for storing analysis results)
// 2. Create artifact using the provided factory function
// 3. Manually inject dependencies into the local service:
//   - Applier: Merges layers and applies analysis results
//   - OS Scanner: Detects OS packages and vulnerabilities
//   - Language Scanner: Detects language-specific packages and vulnerabilities
//   - Vulnerability Client: Fetches vulnerability information from the database
//
// The function returns:
//   - scan.Service: The configured scanning service with all dependencies injected
//   - cleanup function: Must be called to properly release resources
//   - error: If any initialization fails
//
// Dependency injection graph (all manually wired):
//
//	Cache → Applier → LocalService → Artifact → ScanService
//	      ↘ OS Scanner ↗
//	      ↘ Lang Scanner ↗
//	      ↘ Vuln Client ↗
func createLocalService(conf ScannerConfig, newArtifact newArtifactFunc) (scan.Service, func(), error) {
	// Use cache from config, or create a new one if not provided (for backward compatibility)
	c := conf.Cache
	var cleanupCache func()
	if c == nil {
		var err error
		c, cleanupCache, err = cache.New(conf.CacheOptions)
		if err != nil {
			return scan.Service{}, nil, xerrors.Errorf("unable to initialize cache: %w", err)
		}
	}

	app := applier.NewApplier(c)
	osScanner := ospkg.NewScanner()
	langScanner := langpkg.NewScanner()
	vulnClient := vulnerability.NewClient(db.Config{})
	service := local.NewService(app, osScanner, langScanner, vulnClient)

	art, cleanupArtifact, err := newArtifact(c)
	if err != nil {
		// Only cleanup cache if we created it locally
		if cleanupCache != nil {
			cleanupCache()
		}
		return scan.Service{}, nil, xerrors.Errorf("unable to initialize artifact: %w", err)
	}

	return scan.NewService(service, art), func() {
		cleanupArtifact()
		// Only cleanup cache if we created it locally
		if cleanupCache != nil {
			cleanupCache()
		}
	}, nil
}

// createRemoteService creates a remote scanning service using manual dependency injection.
// This replaces the previous Wire-based code generation with explicit dependency management.
//
// Dependency injection process:
// 1. Initialize remote cache (for caching results on server side)
// 2. Create artifact using the provided factory function
// 3. Manually inject the RPC client service to communicate with the server
//
// The function returns:
//   - scan.Service: The configured scanning service with all dependencies injected
//   - cleanup function: Must be called to properly release resources
//   - error: If any initialization fails
//
// Dependency injection graph (all manually wired):
//
//	RemoteCache → Artifact → ClientService → ScanService
//	                        ↗
//	           Trivy Server (handles scanning logic)
func createRemoteService(ctx context.Context, conf ScannerConfig, newArtifact newArtifactFunc) (scan.Service, func(), error) {
	remoteCache := cache.NewRemoteCache(ctx, conf.RemoteCacheOptions)

	art, cleanupArtifact, err := newArtifact(remoteCache)
	if err != nil {
		return scan.Service{}, nil, err
	}

	service := client.NewService(conf.ServerOption)
	return scan.NewService(service, art), cleanupArtifact, nil
}
