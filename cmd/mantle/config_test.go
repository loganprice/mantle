package main

import (
	"context"
	"fmt"
	"reflect"
	"testing"

	"github.com/moby/buildkit/frontend/gateway/client"
)

func TestExtractDefaultArgs(t *testing.T) {
	tests := []struct {
		desc string
		data []byte
		want map[string]string
	}{
		{
			desc: "simple args block",
			data: []byte(`version: "1.0"
args:
  FOO: bar
  BAZ: 123
pipeline:
`),
			want: map[string]string{
				"FOO": "bar",
				"BAZ": "123",
			},
		},
		{
			desc: "args block with comments and empty lines",
			data: []byte(`args:
  # some comment
  APP_VERSION: latest
  
  TARGET_OS: linux
`),
			want: map[string]string{
				"APP_VERSION": "latest",
				"TARGET_OS":   "linux",
			},
		},
		{
			desc: "no args block",
			data: []byte(`version: "1.0"
pipeline: []`),
			want: map[string]string{},
		},
		{
			desc: "args with golang template vars inside (should evaluate literally here)",
			data: []byte(`args:
  DEBUG: "{{ .BuildArgs.FOO }}"
`),
			want: map[string]string{
				"DEBUG": "{{ .BuildArgs.FOO }}",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			got := extractDefaultArgs(tc.data)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("extractDefaultArgs() = %v, want %v", got, tc.want)
			}
		})
	}
}

// -- BuildKit Mock --

type mockClientConfig struct {
	client.Client
	opts map[string]string
	data []byte
	err  error
}

func (m *mockClientConfig) BuildOpts() client.BuildOpts {
	return client.BuildOpts{Opts: m.opts}
}

func (m *mockClientConfig) Solve(_ context.Context, _ client.SolveRequest) (*client.Result, error) {
	if m.err != nil {
		return nil, m.err
	}
	res := client.NewResult()
	res.SetRef(&mockReferenceConfig{data: m.data})
	return res, nil
}

type mockReferenceConfig struct {
	client.Reference
	data []byte
}

func (m *mockReferenceConfig) ReadFile(_ context.Context, _ client.ReadRequest) ([]byte, error) {
	if m.data == nil {
		return nil, fmt.Errorf("file not found")
	}
	return m.data, nil
}

func TestGetBuildArgs(t *testing.T) {
	opts := map[string]string{
		"build-arg:FOO": "bar",
		"ignoreme":      "true",
	}
	mc := &mockClientConfig{opts: opts}

	args := getBuildArgs(mc)

	if len(args) != 1 || args["FOO"] != "bar" {
		t.Errorf("expected 1 build arg 'FOO=bar', got: %v", args)
	}
}

func TestGetTargetPlatforms(t *testing.T) {
	// Standard
	mc1 := &mockClientConfig{opts: map[string]string{"platform": "linux/amd64,linux/arm64"}}
	archs1 := getTargetPlatforms(mc1)
	if len(archs1) != 2 || archs1[0] != "amd64" || archs1[1] != "arm64" {
		t.Errorf("failed multi-platform parse: %v", archs1)
	}

	// Just arch
	mc2 := &mockClientConfig{opts: map[string]string{"platform": "riscv64"}}
	archs2 := getTargetPlatforms(mc2)
	if len(archs2) != 1 || archs2[0] != "riscv64" {
		t.Errorf("failed bare arch parse: %v", archs2)
	}

	// Default empty
	mc3 := &mockClientConfig{}
	archs3 := getTargetPlatforms(mc3)
	if len(archs3) != 1 {
		t.Errorf("expected runtime fallback: %v", archs3)
	}
}

func TestLoadConfig(t *testing.T) {
	yamlData := `version: "1.0"
contents:
  packages: ["wolfi-baselayout"]
  repositories: ["https://example.com/wolfi"]
  keyring: ["https://example.com/wolfi-signing.rsa.pub"]
runtime:
  user: 65532
  workdir: /tmp
  entrypoint: ["{{ .BuildArgs.TOOL }}"]
`
	mc := &mockClientConfig{
		data: []byte(yamlData),
		opts: map[string]string{"build-arg:TOOL": "/bin/sh"},
	}

	spec, err := loadConfig(context.Background(), mc, "amd64")
	if err != nil {
		t.Fatalf("unexpected fail: %v", err)
	}
	if spec.Runtime.Entrypoint[0] != "/bin/sh" {
		t.Errorf("expected /bin/sh entrypoint templated from build arg")
	}

	// Missing yaml error
	mcErr := &mockClientConfig{err: fmt.Errorf("solve timeout")}
	_, err = loadConfig(context.Background(), mcErr, "amd64")
	if err == nil {
		t.Fatal("expected error from BuildKit solve block")
	}
}
