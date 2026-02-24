package main

import (
	"context"
	"log/slog"

	"github.com/moby/buildkit/frontend/gateway/client"

	"github.com/loganprice/mantle/internal/assembler"
	"github.com/loganprice/mantle/internal/sbom"
	"github.com/loganprice/mantle/pkg/config"
)

// generateAndEmbedSBOM generates a CycloneDX SBOM, embeds it into the LLB
// state as a file at /sbom.cdx.json, solves it, and returns the new reference
// along with the raw JSON for metadata association.
func generateAndEmbedSBOM(ctx context.Context, c client.Client, ref client.Reference, spec *config.Spec, asmRes *assembler.Result) ([]byte, client.Reference, error) {
	scanner := sbom.NewScanner()
	components := scanner.Scan(ctx, ref, asmRes.PackageInfos)
	sbomJSON, err := sbom.GenerateSBOM(components, spec)
	if err != nil {
		return nil, nil, err
	}

	slog.Info("[mantle] SBOM generated", slog.Int("components", len(components)))

	// The SBOM is returned to be attached as OCI metadata (annotations, labels, or inline config)
	// instead of embedded in the image filesystem to preserve reproducible builds.
	finalState := asmRes.State

	def, err := finalState.Marshal(ctx)
	if err != nil {
		return nil, nil, err
	}

	finalRes, err := c.Solve(ctx, client.SolveRequest{
		Definition: def.ToPB(),
	})
	if err != nil {
		return nil, nil, err
	}

	finalRef, err := finalRes.SingleRef()
	if err != nil {
		return nil, nil, err
	}

	return sbomJSON, finalRef, nil
}
