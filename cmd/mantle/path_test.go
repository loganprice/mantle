package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/moby/buildkit/frontend/gateway/client"
	ocispecs "github.com/opencontainers/image-spec/specs-go/v1"
	fstypes "github.com/tonistiigi/fsutil/types"

	"github.com/loganprice/mantle/internal/assembler"
)

// mockReference implements client.Reference for testing path discovery
type mockReference struct {
	client.Reference
	dirs map[string]bool
}

func (m *mockReference) ReadDir(ctx context.Context, req client.ReadDirRequest) ([]*fstypes.Stat, error) {
	targetDir := filepath.Clean(req.Path)
	if !strings.HasSuffix(targetDir, "/") {
		targetDir += "/"
	}

	seen := make(map[string]bool)
	var entries []*fstypes.Stat

	found := false
	for p := range m.dirs {
		if strings.HasPrefix(p, targetDir) {
			found = true
			rel := strings.TrimPrefix(p, targetDir)
			parts := strings.SplitN(rel, "/", 2)

			childName := parts[0]
			if childName == "" || seen[childName] {
				continue
			}
			seen[childName] = true

			// Emulate all sub-elements as directories
			entries = append(entries, &fstypes.Stat{
				Path: childName,
				Mode: uint32(0755 | os.ModeDir), // Dir bit
			})
		}
	}

	if !found {
		return nil, fmt.Errorf("dir not found")
	}
	return entries, nil
}

func TestAutoConfigurePATH(t *testing.T) {
	mock := &mockReference{
		dirs: map[string]bool{
			"/usr/lib/my-app/bin/": true,
			"/opt/tools/bin/":      true,
			"/usr/lib/ignored/":    true, // no bin
		},
	}

	cfg := &assembler.ImageConfig{
		OCI: ocispecs.ImageConfig{
			Env: []string{"FOO=bar"}, // PATH not yet set
		},
	}

	autoConfigurePATH(context.Background(), mock, cfg)

	if len(cfg.OCI.Env) != 2 {
		t.Fatalf("expected 2 env vars (FOO + PATH), got %d", len(cfg.OCI.Env))
	}

	pathVar := cfg.OCI.Env[1]
	if !strings.HasPrefix(pathVar, "PATH=") {
		t.Errorf("expected PATH variable at index 1, got %s", pathVar)
	}

	// Verify the dynamically discovered paths are cleanly prepended
	if !strings.Contains(pathVar, "/opt/tools/bin") {
		t.Errorf("auto-path missing /opt/tools/bin: %s", pathVar)
	}
	if !strings.Contains(pathVar, "/usr/lib/my-app/bin") {
		t.Errorf("auto-path missing /usr/lib/my-app/bin: %s", pathVar)
	}
}

func TestAutoConfigurePATH_AlreadySetByUser(t *testing.T) {
	mock := &mockReference{
		dirs: map[string]bool{
			"/opt/tools/bin/": true,
		},
	}

	cfg := &assembler.ImageConfig{
		OCI: ocispecs.ImageConfig{
			Env: []string{"PATH=/custom/bin"}, // User manually overrode PATH in runtime env
		},
	}

	autoConfigurePATH(context.Background(), mock, cfg)

	if len(cfg.OCI.Env) != 1 || cfg.OCI.Env[0] != "PATH=/custom/bin" {
		t.Errorf("expected user-defined PATH to remain untouched, got %v", cfg.OCI.Env)
	}
}
