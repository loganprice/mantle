package assembler

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/loganprice/mantle/pkg/config"
)

func TestNewImageConfig(t *testing.T) {
	spec := &config.Spec{
		Version: "1.0",
		Runtime: config.Runtime{
			User:       65532,
			Workdir:    "/app",
			Entrypoint: []string{"/bin/sh"},
			Args:       []string{"-c", "echo hello"},
			Env: map[string]string{
				"FOO": "bar",
			},
		},
	}

	ic := NewImageConfig(spec, "amd64")

	if ic.OS != "linux" {
		t.Errorf("expected OS linux, got %s", ic.OS)
	}
	if ic.Arch != "amd64" {
		t.Errorf("expected Arch amd64, got %s", ic.Arch)
	}

	if ic.OCI.User != "65532" {
		t.Errorf("expected user 65532, got %s", ic.OCI.User)
	}
	if ic.OCI.WorkingDir != "/app" {
		t.Errorf("expected workdir /app, got %s", ic.OCI.WorkingDir)
	}
	if len(ic.OCI.Entrypoint) != 1 || ic.OCI.Entrypoint[0] != "/bin/sh" {
		t.Errorf("expected entrypoint /bin/sh, got %v", ic.OCI.Entrypoint)
	}
	if len(ic.OCI.Env) != 1 || ic.OCI.Env[0] != "FOO=bar" {
		t.Errorf("expected env FOO=bar, got %v", ic.OCI.Env)
	}

	// Labels
	if ic.OCI.Labels["io.mantle.version"] != "1.0" {
		t.Errorf("expected version 1.0, got %s", ic.OCI.Labels["io.mantle.version"])
	}
	if ic.OCI.Labels["io.mantle.shell-less"] != "true" {
		t.Errorf("expected shell-less true, got %s", ic.OCI.Labels["io.mantle.shell-less"])
	}
}

func TestGetCreationTime(t *testing.T) {
	// Test without SOURCE_DATE_EPOCH
	_ = os.Unsetenv("SOURCE_DATE_EPOCH")
	nowStr := getCreationTime()
	if _, err := time.Parse(time.RFC3339, nowStr); err != nil {
		t.Errorf("expected valid RFC3339 without epoch, got %s: %v", nowStr, err)
	}

	// Test with valid SOURCE_DATE_EPOCH (e.g. 1000000)
	err := os.Setenv("SOURCE_DATE_EPOCH", "1000000")
	if err != nil {
		t.Fatalf("failed to set SOURCE_DATE_EPOCH: %v", err)
	}
	defer func() { _ = os.Unsetenv("SOURCE_DATE_EPOCH") }()

	epochStr := getCreationTime()
	if epochStr != "1970-01-12T13:46:40Z" {
		t.Errorf("expected 1970 UTC timestamp for epoch 1000000, got %s", epochStr)
	}

	// Test with invalid SOURCE_DATE_EPOCH
	_ = os.Setenv("SOURCE_DATE_EPOCH", "invalid")
	invalidStr := getCreationTime()
	if _, err := time.Parse(time.RFC3339, invalidStr); err != nil {
		t.Errorf("expected valid fallback RFC3339 on invalid epoch, got %s: %v", invalidStr, err)
	}
}

func TestToJSON(t *testing.T) {
	ic := &ImageConfig{
		OS:   "linux",
		Arch: "arm64",
	}

	data, err := ic.ToJSON()
	if err != nil {
		t.Fatalf("failed to marshal to JSON: %v", err)
	}

	strData := string(data)
	if !strings.Contains(strData, `"os":"linux"`) {
		t.Errorf("expected JSON to contain os:linux, got %s", strData)
	}
	if !strings.Contains(strData, `"architecture":"arm64"`) {
		t.Errorf("expected JSON to contain architecture:arm64, got %s", strData)
	}
}
