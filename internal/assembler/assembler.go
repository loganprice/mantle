// Package assembler orchestrates the build process by resolving packages,
// fetching assets, running pipelines, and assembling the final OCI image.
package assembler

import (
	"context"
	"fmt"

	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/frontend/gateway/client"
	ocispecs "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/loganprice/mantle/internal/assets"
	"github.com/loganprice/mantle/internal/pipeline"
	"github.com/loganprice/mantle/internal/resolver"
	"github.com/loganprice/mantle/internal/security"
	"github.com/loganprice/mantle/internal/signature"
	"github.com/loganprice/mantle/pkg/config"
)

// Result contains the assembled LLB definition and OCI image configuration.
type Result struct {
	// Definition is the serialized LLB graph ready for BuildKit to solve.
	Definition *llb.Definition
	// State is the final LLB state, allowing post-processing.
	State llb.State
	// Config is the OCI image configuration for the final image.
	Config *ImageConfig
	// PackageInfos holds resolved Wolfi package metadata for SBOM cross-checking.
	PackageInfos []resolver.PackageInfo
}

// Assembler orchestrates the full build graph construction.
type Assembler struct {
	arch        string
	ignoreCache bool
	forcePull   bool
}

// New creates an Assembler for the given target architecture.
func New(arch string, ignoreCache, forcePull bool) *Assembler {
	return &Assembler{arch: arch, ignoreCache: ignoreCache, forcePull: forcePull}
}

// Assemble builds the complete LLB graph from an mantle.yaml spec.
// It returns a Result containing the LLB definition and OCI image config.
//
// Build order:
//  1. Resolve Wolfi packages → base OS layer
//  2. Fetch multi-source assets → asset layers
//  3. Process ephemeral pipeline steps → pipeline layers
//  4. Merge all layers → single rootfs
//  5. Apply security hardening (remove shells)
//  6. Marshal to LLB definition
func (a *Assembler) Assemble(ctx context.Context, c client.Client, spec *config.Spec, localCtx llb.State) (*Result, error) {
	// -- Security pre-checks --
	if err := security.EnforceNoRoot(spec); err != nil {
		return nil, err
	}

	// -- 1. Keyring + Wolfi package resolution --
	var keyring *signature.Keyring
	if len(spec.Contents.Keyring) > 0 {
		var err error
		keyring, err = signature.FetchKeyring(ctx, c, spec.Contents.Keyring)
		if err != nil {
			return nil, fmt.Errorf("fetching keyring: %w", err)
		}
	}

	res := resolver.New(resolver.ArchFromPlatform(a.arch),
		resolver.WithIgnoreCache(a.ignoreCache),
		resolver.WithForcePull(a.forcePull),
	)
	pkgState, pkgInfos, err := res.Resolve(ctx, c, spec.Contents, keyring)
	if err != nil {
		return nil, fmt.Errorf("resolving packages: %w", err)
	}

	// Collect all layers to merge
	layers := []llb.State{pkgState}

	// -- 2. Multi-source asset fetching --
	if len(spec.Assets) > 0 {
		fetcher := assets.NewFetcher(a.ignoreCache, a.forcePull)
		assetStates, err := fetcher.FetchAll(spec.Assets, localCtx)
		if err != nil {
			return nil, fmt.Errorf("fetching assets: %w", err)
		}
		layers = append(layers, assetStates...)
	}

	// -- 3. Ephemeral pipeline stages --
	if len(spec.Pipeline) > 0 {
		// Pipeline steps need access to both packages and assets (e.g. source code)
		// Since 'layers' contains [pkgState, asset1, asset2...], merging them creates the base.
		pipelineBase := pkgState
		if len(layers) > 1 {
			pipelineBase = llb.Merge(layers, llb.WithCustomName("[mantle] merge base for pipeline"))
		}

		proc := pipeline.NewProcessor(a.ignoreCache, a.forcePull)
		pipelineStates, err := proc.Process(spec.Pipeline, pipelineBase)
		if err != nil {
			return nil, fmt.Errorf("processing pipeline: %w", err)
		}
		layers = append(layers, pipelineStates...)
	}

	// -- 4. Merge all layers --
	var rootfs llb.State
	if len(layers) == 1 {
		rootfs = layers[0]
	} else {
		rootfs = llb.Merge(layers, llb.WithCustomName("[mantle] merge final rootfs"))
	}

	// -- 5. Security hardening: remove shells --
	// Allow users to explicitly opt-out of shell removal for debugging.
	removeShells := true
	if spec.Runtime.Options != nil && spec.Runtime.Options.RemoveShells != nil {
		removeShells = *spec.Runtime.Options.RemoveShells
	}
	if removeShells {
		rootfs = security.RemoveShells(rootfs)
	}

	// -- 6. Marshal to LLB definition --
	p := ocispecs.Platform{OS: "linux", Architecture: a.arch}
	def, err := rootfs.Marshal(ctx, llb.Platform(p))
	if err != nil {
		return nil, fmt.Errorf("marshaling LLB: %w", err)
	}

	// -- 7. Image Configuration --
	// Builds the OCI image configuration (ImageConfig) from the runtime spec
	// Uses OCI arch (arm64/amd64), not APK arch (aarch64/x86_64)
	imgConfig := NewImageConfig(spec, a.arch)

	return &Result{
		Definition:   def,
		State:        rootfs,
		Config:       imgConfig,
		PackageInfos: pkgInfos,
	}, nil
}
