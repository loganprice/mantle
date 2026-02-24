package main

import (
	"context"
	"testing"

	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/frontend/gateway/client"
	fstypes "github.com/tonistiigi/fsutil/types"

	"github.com/loganprice/mantle/internal/assembler"
	"github.com/loganprice/mantle/pkg/config"
)

type mockClientSBOM struct {
	client.Client
}

func (m *mockClientSBOM) Solve(_ context.Context, req client.SolveRequest) (*client.Result, error) {
	res := client.NewResult()
	res.SetRef(&mockReferenceSBOM{})
	return res, nil
}

type mockReferenceSBOM struct {
	client.Reference
}

func (m *mockReferenceSBOM) ReadDir(_ context.Context, req client.ReadDirRequest) ([]*fstypes.Stat, error) {
	// Let's pretend there are no files, scanner will just output base SBOM
	return nil, nil
}

func (m *mockReferenceSBOM) StatFile(_ context.Context, req client.StatRequest) (*fstypes.Stat, error) {
	return nil, nil
}
func (m *mockReferenceSBOM) ReadFile(_ context.Context, req client.ReadRequest) ([]byte, error) {
	return nil, nil
}

func TestGenerateAndEmbedSBOM(t *testing.T) {
	a := assembler.New("amd64", false, false)
	spec := &config.Spec{
		Runtime: config.Runtime{User: 65532},
	}

	// Build a dummy scratch result map
	res, err := a.Assemble(context.Background(), &mockClientSBOM{}, spec, llb.Scratch())
	if err != nil {
		t.Fatalf("unexpected assembler failure natively: %v", err)
	}

	sbomJSON, ref, err := generateAndEmbedSBOM(context.Background(), &mockClientSBOM{}, &mockReferenceSBOM{}, spec, res)
	if err != nil {
		t.Fatalf("unexpected fail generating the SBOM natively: %v", err)
	}

	if len(sbomJSON) == 0 {
		t.Errorf("expected valid SBOM output JSON bytes")
	}
	if ref == nil {
		t.Errorf("expected LLB ref structure passed back natively")
	}
}
