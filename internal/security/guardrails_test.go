package security

import (
	"context"
	"testing"

	"github.com/moby/buildkit/client/llb"

	"github.com/loganprice/mantle/pkg/config"
)

func TestEnforceNoRoot(t *testing.T) {
	// Root user without force_root should fail
	spec := &config.Spec{
		Runtime: config.Runtime{User: 0},
	}
	if err := EnforceNoRoot(spec); err == nil {
		t.Fatal("expected error for root user without force_root")
	}

	// Root user with force_root should pass
	spec.Runtime.ForceRoot = true
	if err := EnforceNoRoot(spec); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Non-root user should always pass
	spec = &config.Spec{
		Runtime: config.Runtime{User: 65532},
	}
	if err := EnforceNoRoot(spec); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestShellPathsList(t *testing.T) {
	// Ensure we cover the common shells and utilities
	mustContain := []string{"/bin/sh", "/bin/bash", "/bin/ash", "/bin/busybox", "/sbin/apk"}
	for _, expected := range mustContain {
		found := false
		for _, sp := range shellPaths {
			if sp == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("shellPaths missing %q", expected)
		}
	}
}

func TestRemoveShells(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "base case"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// RemoveShells simply chains llb.Rm on an empty state.
			// Buildkit internal state verification is complex, but we can verify it doesn't panic
			// and returns a valid state struct.
			state := llb.Scratch()
			result := RemoveShells(state)

			// Just verify it produced a valid state that can be marshaled
			ctx := context.TODO()
			if _, err := result.Marshal(ctx); err != nil {
				t.Fatalf("unexpected error marshaling state: %v", err)
			}
		})
	}
}
