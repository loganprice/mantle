package sbom

import (
	"encoding/json"
	"testing"

	"github.com/loganprice/mantle/pkg/config"
)

func TestGenerateSBOM(t *testing.T) {
	scanned := []Component{
		{
			Type:    "library",
			Name:    "python-3.12",
			Version: "3.12.8-r3",
			PURL:    "pkg:apk/wolfi/python-3.12@3.12.8-r3",
		},
		{
			Type:    "library",
			Name:    "requests",
			Version: "2.31.0",
			PURL:    "pkg:pypi/requests@2.31.0",
		},
	}

	spec := &config.Spec{
		Version: "1.0",
		Pipeline: []config.Step{
			{Name: "pip-install", Uses: "python:3.12-alpine"},
		},
		Assets: []config.Asset{
			{Name: "app", Source: "local://./src", Destination: "/app"},
			{Name: "config", Source: "https://example.com/config.json", Destination: "/etc/config.json", SHA256: "abc123"},
		},
	}

	data, err := GenerateSBOM(scanned, spec)
	if err != nil {
		t.Fatalf("GenerateSBOM error: %v", err)
	}

	var bom BOM
	if err := json.Unmarshal(data, &bom); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	// Validate top-level
	if bom.BOMFormat != "CycloneDX" {
		t.Errorf("bomFormat = %q, want CycloneDX", bom.BOMFormat)
	}
	if bom.SpecVersion != "1.5" {
		t.Errorf("specVersion = %q, want 1.5", bom.SpecVersion)
	}
	if len(bom.Metadata.Tools) != 1 || bom.Metadata.Tools[0].Name != "mantle" {
		t.Errorf("expected mantle tool in metadata, got %+v", bom.Metadata.Tools)
	}

	// 2 scanned + 1 pipeline image + 2 assets = 5
	if len(bom.Components) != 5 {
		t.Errorf("components count = %d, want 5", len(bom.Components))
		for i, c := range bom.Components {
			t.Logf("  [%d] type=%s name=%s", i, c.Type, c.Name)
		}
	}

	// Find the pipeline image component
	found := false
	for _, c := range bom.Components {
		if c.Type == "container" && c.Name == "python" {
			found = true
			if c.Version != "3.12-alpine" {
				t.Errorf("pipeline image version = %q, want %q", c.Version, "3.12-alpine")
			}
			break
		}
	}
	if !found {
		t.Error("expected pipeline image component for python:3.12-alpine")
	}
}

func TestGenerateSBOMEmpty(t *testing.T) {
	data, err := GenerateSBOM(nil, &config.Spec{Version: "1.0"})
	if err != nil {
		t.Fatalf("GenerateSBOM error: %v", err)
	}

	var bom BOM
	if err := json.Unmarshal(data, &bom); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if len(bom.Components) != 0 {
		t.Errorf("expected 0 components for empty input, got %d", len(bom.Components))
	}
}

func TestParseImageRef(t *testing.T) {
	tests := []struct {
		ref     string
		name    string
		version string
	}{
		{"python:3.12-alpine", "python", "3.12-alpine"},
		{"ghcr.io/org/tools:latest", "ghcr.io/org/tools", "latest"},
		{"alpine", "alpine", "latest"},
		{"registry.local:5000/my-image:1.0", "registry.local:5000/my-image", "1.0"},
		{"registry.local:5000/my-image", "registry.local:5000/my-image", "latest"},
		{"ghcr.io/org/tools@sha256:abcdef", "ghcr.io/org/tools", "sha256:abcdef"},
	}

	for _, tt := range tests {
		name, version := parseImageRef(tt.ref)
		if name != tt.name || version != tt.version {
			t.Errorf("parseImageRef(%q) = (%q, %q), want (%q, %q)", tt.ref, name, version, tt.name, tt.version)
		}
	}
}
