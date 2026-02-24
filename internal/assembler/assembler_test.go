package assembler

import (
	"context"
	"fmt"
	"testing"

	"github.com/loganprice/mantle/pkg/config"
	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/frontend/gateway/client"
)

func TestNewAssembler(t *testing.T) {
	asm := New("amd64", true, false)
	if asm.arch != "amd64" {
		t.Errorf("expected arch amd64, got %s", asm.arch)
	}
	if !asm.ignoreCache {
		t.Errorf("expected ignoreCache true, got false")
	}
	if asm.forcePull {
		t.Errorf("expected forcePull false, got true")
	}
}

// mockClient implementation to intercept BuildKit solver logic
type mockClient struct {
	client.Client
	expectErr error
}

func (m *mockClient) Solve(_ context.Context, req client.SolveRequest) (*client.Result, error) {
	if m.expectErr != nil {
		return nil, m.expectErr
	}
	res := client.NewResult()
	return res, nil
}

func TestAssemble_Success_Empty(t *testing.T) {
	a := New("amd64", false, false)
	spec := &config.Spec{
		Runtime: config.Runtime{User: 65532},
	}

	res, err := a.Assemble(context.Background(), &mockClient{}, spec, llb.Scratch())
	if err != nil {
		t.Fatalf("unexpected failure on empty assemble: %v", err)
	}
	if res.Definition == nil {
		t.Errorf("expected valid LLB definition")
	}
	if res.Config == nil {
		t.Errorf("expected valid image config")
	}
}

func TestAssemble_NoRoot_Error(t *testing.T) {
	a := New("amd64", false, false)

	spec := &config.Spec{
		Runtime: config.Runtime{
			User: 0, // Should be rejected by EnforceNoRoot (requires force_root)
		},
	}

	_, err := a.Assemble(context.Background(), nil, spec, llb.Scratch())
	if err == nil {
		t.Fatal("expected error rejecting root user")
	}
}

func TestAssemble_KeyringError(t *testing.T) {
	a := New("amd64", false, false)

	spec := &config.Spec{
		Runtime: config.Runtime{User: 65532},
		Contents: config.Contents{
			Keyring: []string{"https://x.com/invalid"}, // forces FetchKeyring which calls Solve
		},
	}

	_, err := a.Assemble(context.Background(), &mockClient{expectErr: fmt.Errorf("timeout")}, spec, llb.Scratch())
	if err == nil {
		t.Fatal("expected error propagating from keyring solver")
	}
}

func TestAssemble_FullFlow(t *testing.T) {
	a := New("amd64", false, false)
	spec := &config.Spec{
		Runtime: config.Runtime{User: 65532},
		Assets: []config.Asset{
			{Name: "src", Source: "local://.", Destination: "/src"},
		},
		Pipeline: []config.Step{
			{Name: "build", Uses: "alpine", Run: []string{"echo test"}},
		},
	}

	res, err := a.Assemble(context.Background(), &mockClient{}, spec, llb.Scratch())
	if err != nil {
		t.Fatalf("unexpected failure on full assemble flow: %v", err)
	}
	if res.Definition == nil || res.Config == nil {
		t.Errorf("expected valid definition and image config")
	}
}

func TestAssemble_RemoveShells_Options(t *testing.T) {
	a := New("amd64", false, false)

	boolPtr := func(b bool) *bool { return &b }

	tests := []struct {
		name         string
		removeShells *bool
	}{
		{"default true (nil)", nil},
		{"explicit true", boolPtr(true)},
		{"explicit false", boolPtr(false)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec := &config.Spec{
				Runtime: config.Runtime{
					User: 65532,
					Options: &config.RuntimeOptions{
						RemoveShells: tt.removeShells,
					},
				},
			}

			res, err := a.Assemble(context.Background(), &mockClient{}, spec, llb.Scratch())
			if err != nil {
				t.Fatalf("unexpected error parsing remove_shells option: %v", err)
			}
			if res.Definition == nil {
				t.Errorf("expected valid definition")
			}
		})
	}
}

func TestAssemble_AssetError(t *testing.T) {
	a := New("amd64", false, false)
	spec := &config.Spec{
		Runtime: config.Runtime{User: 65532},
		Assets: []config.Asset{
			{Name: "bad", Source: "invalid://bad", Destination: "/bad"},
		},
	}

	_, err := a.Assemble(context.Background(), &mockClient{}, spec, llb.Scratch())
	if err == nil {
		t.Fatal("expected error on unsupported asset scheme")
	}
}
