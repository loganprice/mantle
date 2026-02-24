// Mantle (mantle) — A declarative BuildKit frontend for secure,
// zero-CVE OCI artifacts.
//
// This binary is the BuildKit frontend entrypoint. It reads mantle.yaml
// from the build context, converts it into an LLB graph, and returns
// the result via the BuildKit gateway client.
//
// Usage (as a syntax directive in mantle.yaml):
//
//	# syntax=registry.labs.io/mantle:v1
//	version: "1.0"
//	...
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"

	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/exporter/containerimage/exptypes"
	"github.com/moby/buildkit/frontend/gateway/client"
	"github.com/moby/buildkit/frontend/gateway/grpcclient"
	"github.com/moby/buildkit/util/appcontext"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	"golang.org/x/sync/errgroup"

	"github.com/loganprice/mantle/internal/assembler"
)

func main() {
	if err := grpcclient.RunFromEnvironment(appcontext.Context(), Build); err != nil {
		slog.Error("mantle: " + err.Error())
		os.Exit(1)
	}
}

// Build is the BuildKit frontend entry point. It is called by BuildKit
// when processing a build request that uses this frontend.
func Build(ctx context.Context, c client.Client) (*client.Result, error) {
	// 1. Parse and validate the mantle.yaml spec from the build context
	opts := c.BuildOpts().Opts
	_, ignoreCache := opts["no-cache"]
	forcePull := opts["image-resolve-mode"] == "pull"

	// 2. Determine target architectures
	archs := getTargetPlatforms(c)

	res := client.NewResult()

	// Initialize result objects map
	// BuildKit gateway client requires keys to be in the format of platform-specific keys
	// However, we just iteratively add references and metadata tied to each platform

	var expPlatforms exptypes.Platforms

	type platformResult struct {
		platformKey string
		ref         client.Reference
		imgJSON     []byte
		sbomJSON    []byte
	}

	results := make([]platformResult, len(archs))
	eg, egCtx := errgroup.WithContext(ctx)

	for i, arch := range archs {
		i, arch := i, arch // capture for goroutine
		platformKey := "linux/" + arch

		expPlatforms.Platforms = append(expPlatforms.Platforms, exptypes.Platform{
			ID: platformKey,
			Platform: v1.Platform{
				OS:           "linux",
				Architecture: arch,
			},
		})

		eg.Go(func() error {
			spec, err := loadConfig(egCtx, c, arch)
			if err != nil {
				return fmt.Errorf("parsing configuration for %s: %w", platformKey, err)
			}

			// 3. Assemble the build graph (packages, assets, pipelines)
			localCtx := llb.Local("context", llb.WithCustomName("[mantle] build context"))
			asm := assembler.New(arch, ignoreCache, forcePull)
			asmRes, err := asm.Assemble(egCtx, c, spec, localCtx)
			if err != nil {
				return fmt.Errorf("assembling build for %s: %w", platformKey, err)
			}

			// 4. Solve the LLB definition to generate the filesystem
			solveRes, err := c.Solve(egCtx, client.SolveRequest{
				Definition:  asmRes.Definition.ToPB(),
				FrontendOpt: opts,
			})
			if err != nil {
				return fmt.Errorf("solving build graph for %s: %w", platformKey, err)
			}

			ref, err := solveRes.SingleRef()
			if err != nil {
				return fmt.Errorf("getting build reference for %s: %w", platformKey, err)
			}

			// 5. Auto-discover PATH based on installed packages
			autoConfigurePATH(egCtx, ref, asmRes.Config)

			// 6. Generate and embed SBOM
			var sbomJSON []byte
			if generatedSBOM, sbomRef, err := generateAndEmbedSBOM(egCtx, c, ref, spec, asmRes); err != nil {
				slog.Warn("[mantle] Warning: SBOM generation failed: " + err.Error())
			} else {
				ref = sbomRef // Use the new reference containing the embedded SBOM
				sbomJSON = generatedSBOM
			}

			// 7. Attach the OCI image config and metadata
			imgJSON, err := asmRes.Config.ToJSON()
			if err != nil {
				return fmt.Errorf("marshaling image config for %s: %w", platformKey, err)
			}

			// Store safely into predefined index without mutex
			results[i] = platformResult{
				platformKey: platformKey,
				ref:         ref,
				imgJSON:     imgJSON,
				sbomJSON:    sbomJSON,
			}
			return nil
		})
	}

	if err := eg.Wait(); err != nil {
		return nil, err
	}

	// Safely aggregate final outputs sequentially into client.Result map
	for _, pr := range results {
		res.AddRef(pr.platformKey, pr.ref)
		res.AddMeta(fmt.Sprintf("containerimage.config/%s", pr.platformKey), pr.imgJSON)

		if pr.sbomJSON != nil {
			res.AddMeta(fmt.Sprintf("containerimage.sbom/%s", pr.platformKey), pr.sbomJSON)
		}
	}

	platformBytes, err := json.Marshal(expPlatforms)
	if err != nil {
		return nil, fmt.Errorf("marshaling exporter platforms: %w", err)
	}
	res.AddMeta(exptypes.ExporterPlatformsKey, platformBytes)

	// Add exporter metadata for OCI compliance
	configData, err := json.Marshal(map[string]string{"name": "mantle"})
	if err != nil {
		return nil, fmt.Errorf("marshaling buildinfo: %w", err)
	}
	res.AddMeta("containerimage.buildinfo", configData)

	return res, nil
}
