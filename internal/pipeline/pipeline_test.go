package pipeline

import (
	"context"
	"reflect"
	"testing"

	"github.com/moby/buildkit/client/llb"

	"github.com/loganprice/mantle/pkg/config"
)

func TestSanitizeCacheID(t *testing.T) {
	tests := []struct {
		stepName string
		target   string
	}{
		{"pip-install", "/root/.cache/pip"},
		{"build", "/tmp/cache"},
	}

	seen := make(map[string]bool)
	for _, tt := range tests {
		got := sanitizeCacheID(tt.stepName, tt.target)
		if len(got) != 64+len("mantle-") {
			t.Errorf("sanitizeCacheID(%q, %q) produced invalid length output: %q", tt.stepName, tt.target, got)
		}
		if seen[got] {
			t.Errorf("sanitizeCacheID produced collision output for %q, %q: %q", tt.stepName, tt.target, got)
		}
		seen[got] = true
	}

	// Verify the collision case identified in code review
	id1 := sanitizeCacheID("build", "/tmp_cache")
	id2 := sanitizeCacheID("build", "/tmp/cache")
	if id1 == id2 {
		t.Errorf("cache ID collision detected between /tmp_cache and /tmp/cache: %s", id1)
	}
}

func TestSortedKeys(t *testing.T) {
	tests := []struct {
		name     string
		input    map[string]string
		expected []string
	}{
		{
			name:     "empty map",
			input:    map[string]string{},
			expected: []string{},
		},
		{
			name: "multiple keys",
			input: map[string]string{
				"ZETA":  "1",
				"ALPHA": "2",
				"BETA":  "3",
			},
			expected: []string{"ALPHA", "BETA", "ZETA"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sortedKeys(tt.input)
			if !reflect.DeepEqual(got, tt.expected) {
				t.Errorf("sortedKeys() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestProcessStep(t *testing.T) {
	p := NewProcessor(false, false)

	tests := []struct {
		name    string
		step    config.Step
		wantErr bool
	}{
		{
			name: "basic step",
			step: config.Step{
				Name: "test",
				Uses: "alpine:latest",
				Run:  []string{"echo hello"},
				Exports: []config.Export{
					{Source: "/tmp/out", Destination: "/out"},
				},
			},
		},
		{
			name: "step with workdir and mounts",
			step: config.Step{
				Name:    "build",
				Uses:    "golang:1.22",
				Workdir: "/app",
				Env: map[string]string{
					"GOPATH": "/go",
				},
				Run: []string{"go build ./"},
				Mounts: []config.Mount{
					{Type: "cache", Target: "/root/.cache/go-build"},
				},
				Exports: []config.Export{
					{Source: "/app/bin", Destination: "/bin"},
				},
			},
		},
	}

	ctx := context.TODO()
	rootfs := llb.Scratch()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := p.processStep(tt.step, rootfs)
			if _, err := out.Marshal(ctx); (err != nil) != tt.wantErr {
				t.Errorf("processStep() marshal error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
