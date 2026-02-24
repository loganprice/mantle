package config

import (
	"testing"
)

func TestParseValidSpec(t *testing.T) {
	yaml := `# syntax=registry.labs.io/mantle:v1
version: "1.0"
contents:
  repositories: ["https://packages.wolfi.dev/os"]
  keyring: ["https://packages.wolfi.dev/os/wolfi-signing.rsa.pub"]
  packages:
    - python-3.12
assets:
  - name: "app"
    source: "local://./src"
    destination: "/app"
runtime:
  user: 65532
  workdir: "/app"
  entrypoint: ["/usr/bin/python3"]
`
	spec, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if spec.Version != "1.0" {
		t.Errorf("version = %q, want %q", spec.Version, "1.0")
	}
	if len(spec.Contents.Packages) != 1 {
		t.Errorf("packages count = %d, want 1", len(spec.Contents.Packages))
	}
	if spec.Contents.Packages[0] != "python-3.12" {
		t.Errorf("package = %q, want %q", spec.Contents.Packages[0], "python-3.12")
	}
	if len(spec.Assets) != 1 {
		t.Errorf("assets count = %d, want 1", len(spec.Assets))
	}
	if spec.Runtime.User != 65532 {
		t.Errorf("user = %d, want 65532", spec.Runtime.User)
	}
}

func TestParseSyntaxDirectiveStripped(t *testing.T) {
	yaml := `# syntax=registry.labs.io/mantle:v1
version: "1.0"
contents:
  repositories: ["https://packages.wolfi.dev/os"]
  keyring: ["https://packages.wolfi.dev/os/wolfi-signing.rsa.pub"]
  packages: ["wolfi-base"]
runtime:
  user: 65532
  workdir: "/app"
  entrypoint: ["/bin/app"]
`
	spec, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if spec.Version != "1.0" {
		t.Errorf("version = %q, want %q", spec.Version, "1.0")
	}
}

func TestParseWithoutSyntaxDirective(t *testing.T) {
	yaml := `version: "1.0"
contents:
  repositories: ["https://packages.wolfi.dev/os"]
  keyring: ["https://packages.wolfi.dev/os/wolfi-signing.rsa.pub"]
  packages: ["wolfi-base"]
runtime:
  user: 65532
  workdir: "/app"
  entrypoint: ["/bin/app"]
`
	spec, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if spec.Version != "1.0" {
		t.Errorf("version = %q, want %q", spec.Version, "1.0")
	}
}

func TestParseInvalidYAML(t *testing.T) {
	_, err := Parse([]byte("not: valid: yaml: ["))
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

func TestParseInvalidVersion(t *testing.T) {
	yaml := `version: "2.0"
contents:
  repositories: ["https://packages.wolfi.dev/os"]
  keyring: ["https://packages.wolfi.dev/os/wolfi-signing.rsa.pub"]
runtime:
  user: 65532
  workdir: "/app"
  entrypoint: ["/bin/app"]
`
	_, err := Parse([]byte(yaml))
	if err == nil {
		t.Fatal("expected error for unsupported version")
	}
}

func TestParseFullSpec(t *testing.T) {
	yaml := `version: "1.0"
contents:
  repositories: ["https://packages.wolfi.dev/os"]
  keyring: ["https://packages.wolfi.dev/os/wolfi-signing.rsa.pub"]
  packages:
    - python-3.12
    - openssl-3.0
assets:
  - name: "app-source"
    source: "local://./src"
    destination: "/app"
    uid: 65532
  - name: "helper"
    source: "oci://ghcr.io/org/tools:latest"
    from_path: "/usr/bin/helper"
    destination: "/usr/bin/helper"
  - name: "config"
    source: "https://example.com/config.json"
    destination: "/etc/app/config.json"
    sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
pipeline:
  - name: "pip-install"
    uses: "wolfi/python-3.12"
    run: ["pip install --prefix=/install -r /app/requirements.txt"]
    mounts:
      - type: cache
        target: "/root/.cache/pip"
    exports: ["/install"]
runtime:
  user: 65532
  workdir: "/app"
  entrypoint: ["/usr/bin/python3"]
  args: ["main.py"]
  env:
    PORT: "8080"
`
	spec, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(spec.Contents.Packages) != 2 {
		t.Errorf("packages count = %d, want 2", len(spec.Contents.Packages))
	}
	if len(spec.Assets) != 3 {
		t.Errorf("assets count = %d, want 3", len(spec.Assets))
	}
	if len(spec.Pipeline) != 1 {
		t.Errorf("pipeline steps = %d, want 1", len(spec.Pipeline))
	}
	if spec.Pipeline[0].Exports[0].Source != "/install" {
		t.Errorf("export source = %q, want %q", spec.Pipeline[0].Exports[0].Source, "/install")
	}

}

func TestExportUnmarshalFallback(t *testing.T) {
	yamlData := `version: "1.0"
contents:
  repositories: ["https://example.com"]
  keyring: ["https://example.com/key"]
  packages: ["dummy"]
pipeline:
  - name: "build"
    uses: "alpine"
    run: ["make"]
    exports:
      - source: "/build/out"
        destination: "/final/out"
runtime:
  user: 65532
  workdir: "/app"
  entrypoint: ["/bin/app"]
`
	spec, err := Parse([]byte(yamlData))
	if err != nil {
		t.Fatalf("unexpected parsing error: %v", err)
	}

	if len(spec.Pipeline[0].Exports) != 1 {
		t.Fatalf("expected 1 export")
	}
	e := spec.Pipeline[0].Exports[0]
	if e.Source != "/build/out" || e.Destination != "/final/out" {
		t.Errorf("unexpected export unmarshal result: %+v", e)
	}
}

func TestNormalizeYAML_ComplexTypes(t *testing.T) {
	// Let's feed raw malformed maps into normalizeYAML directly since it's an internal package helper
	input := map[interface{}]interface{}{
		"stringKey": "stringValue",
		"nestedMap": map[interface{}]interface{}{
			"nestedStr": "value",
			"nestedList": []interface{}{
				map[interface{}]interface{}{"listKey": "listVal"},
			},
		},
	}

	res, err := normalizeYAML(input)
	if err != nil {
		t.Fatalf("unexpected error normalizing: %v", err)
	}

	outMap, ok := res.(map[string]interface{})
	if !ok {
		t.Fatalf("expected root to be map[string]interface{}, got %T", res)
	}

	if outMap["stringKey"] != "stringValue" {
		t.Errorf("expected stringValue")
	}

	// Test error condition
	badInput := map[interface{}]interface{}{
		123: "val", // non-string key
	}
	_, err = normalizeYAML(badInput)
	if err == nil {
		t.Errorf("expected error for non-string key in YAML normalization")
	}

	badNested := map[interface{}]interface{}{
		"key": map[interface{}]interface{}{
			123: "val",
		},
	}
	_, err = normalizeYAML(badNested)
	if err == nil {
		t.Errorf("expected error for nested non-string key in YAML normalization")
	}

	badList := []interface{}{
		map[interface{}]interface{}{
			123: "val",
		},
	}
	_, err = normalizeYAML(badList)
	if err == nil {
		t.Errorf("expected error for list non-string key in YAML normalization")
	}
}
