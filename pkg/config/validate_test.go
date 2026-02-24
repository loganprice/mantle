package config

import (
	"testing"
)

func TestValidateRootUserBlocked(t *testing.T) {
	spec := &Spec{
		Version: "1.0",
		Contents: Contents{
			Repositories: []string{"https://packages.wolfi.dev/os"},
			Keyring:      []string{"https://packages.wolfi.dev/os/wolfi-signing.rsa.pub"},
		},
		Runtime: Runtime{
			User:       0,
			Workdir:    "/app",
			Entrypoint: []string{"/bin/app"},
		},
	}

	err := Validate(spec)
	if err == nil {
		t.Fatal("expected error for root user")
	}
}

func TestValidateRootUserWithForceRoot(t *testing.T) {
	spec := &Spec{
		Version: "1.0",
		Contents: Contents{
			Repositories: []string{"https://packages.wolfi.dev/os"},
			Keyring:      []string{"https://packages.wolfi.dev/os/wolfi-signing.rsa.pub"},
		},
		Runtime: Runtime{
			User:       0,
			ForceRoot:  true,
			Workdir:    "/app",
			Entrypoint: []string{"/bin/app"},
		},
	}

	if err := Validate(spec); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateInvalidAssetSource(t *testing.T) {
	spec := &Spec{
		Version: "1.0",
		Contents: Contents{
			Repositories: []string{"https://packages.wolfi.dev/os"},
			Keyring:      []string{"https://packages.wolfi.dev/os/wolfi-signing.rsa.pub"},
		},
		Assets: []Asset{
			{Name: "bad", Source: "ftp://files.com/foo", Destination: "/foo"},
		},
		Runtime: Runtime{
			User:       65532,
			Workdir:    "/app",
			Entrypoint: []string{"/bin/app"},
		},
	}

	err := Validate(spec)
	if err == nil {
		t.Fatal("expected error for invalid source scheme")
	}
}

func TestValidateValidSources(t *testing.T) {
	tests := []struct {
		source string
	}{
		{"local://./src"},
		{"local://src"},
		{"oci://ghcr.io/org/tools:latest"},
		{"https://example.com/config.json"},
	}

	for _, tt := range tests {
		if err := validateAssetSource(tt.source); err != nil {
			t.Errorf("validateAssetSource(%q) = %v, want nil", tt.source, err)
		}
	}
}

func TestValidateTraversalLocalSource(t *testing.T) {
	spec := &Spec{
		Version: "1.0",
		Contents: Contents{
			Repositories: []string{"https://packages.wolfi.dev/os"},
			Keyring:      []string{"https://packages.wolfi.dev/os/wolfi-signing.rsa.pub"},
		},
		Assets: []Asset{
			{Name: "bad", Source: "local://../../etc/passwd", Destination: "/foo"},
		},
		Runtime: Runtime{
			User:       65532,
			Workdir:    "/app",
			Entrypoint: []string{"/bin/app"},
		},
	}

	err := Validate(spec)
	if err == nil {
		t.Fatal("expected error for path traversing local source")
	}
}

func TestValidateSHA256(t *testing.T) {
	valid := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if err := validateSHA256(valid); err != nil {
		t.Errorf("validateSHA256(valid) = %v, want nil", err)
	}

	// Too short
	if err := validateSHA256("abc123"); err == nil {
		t.Error("expected error for short hash")
	}

	// Invalid hex
	if err := validateSHA256("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"); err == nil {
		t.Error("expected error for invalid hex")
	}
}

func TestValidateDuplicateAssetNames(t *testing.T) {
	spec := &Spec{
		Version: "1.0",
		Contents: Contents{
			Repositories: []string{"https://packages.wolfi.dev/os"},
			Keyring:      []string{"https://packages.wolfi.dev/os/wolfi-signing.rsa.pub"},
		},
		Assets: []Asset{
			{Name: "app", Source: "local://./src", Destination: "/app"},
			{Name: "app", Source: "local://./other", Destination: "/other"},
		},
		Runtime: Runtime{
			User:       65532,
			Workdir:    "/app",
			Entrypoint: []string{"/bin/app"},
		},
	}

	err := Validate(spec)
	if err == nil {
		t.Fatal("expected error for duplicate asset names")
	}
}

func TestValidateEmptyPipelineExports(t *testing.T) {
	spec := &Spec{
		Version: "1.0",
		Contents: Contents{
			Repositories: []string{"https://packages.wolfi.dev/os"},
			Keyring:      []string{"https://packages.wolfi.dev/os/wolfi-signing.rsa.pub"},
		},
		Pipeline: []Step{
			{Name: "build", Uses: "alpine", Run: []string{"make"}, Exports: nil},
		},
		Runtime: Runtime{
			User:       65532,
			Workdir:    "/app",
			Entrypoint: []string{"/bin/app"},
		},
	}

	err := Validate(spec)
	if err == nil {
		t.Fatal("expected error for empty pipeline exports")
	}
}

func TestValidateEmptyPipelineRunString(t *testing.T) {
	spec := &Spec{
		Version: "1.0",
		Contents: Contents{
			Repositories: []string{"https://packages.wolfi.dev/os"},
			Keyring:      []string{"https://packages.wolfi.dev/os/wolfi-signing.rsa.pub"},
		},
		Pipeline: []Step{
			{Name: "build", Uses: "alpine", Run: []string{"make", "   ", "make install"}, Exports: []Export{{Source: "/tmp"}}},
		},
		Runtime: Runtime{
			User:       65532,
			Workdir:    "/app",
			Entrypoint: []string{"/bin/app"},
		},
	}

	err := Validate(spec)
	if err == nil {
		t.Fatal("expected error for empty string inside run array")
	}
}

func TestValidateMissingWorkdir(t *testing.T) {
	spec := &Spec{
		Version: "1.0",
		Contents: Contents{
			Repositories: []string{"https://packages.wolfi.dev/os"},
			Keyring:      []string{"https://packages.wolfi.dev/os/wolfi-signing.rsa.pub"},
		},
		Runtime: Runtime{
			User:       65532,
			Entrypoint: []string{"/bin/app"},
		},
	}

	err := Validate(spec)
	if err == nil {
		t.Fatal("expected error for missing workdir")
	}
}

func TestValidateMissingEntrypoint(t *testing.T) {
	spec := &Spec{
		Version: "1.0",
		Contents: Contents{
			Repositories: []string{"https://packages.wolfi.dev/os"},
			Keyring:      []string{"https://packages.wolfi.dev/os/wolfi-signing.rsa.pub"},
		},
		Runtime: Runtime{
			User:    65532,
			Workdir: "/app",
		},
	}

	err := Validate(spec)
	if err == nil {
		t.Fatal("expected error for missing entrypoint")
	}
}

func TestValidateAbsPath(t *testing.T) {
	tests := []struct {
		path    string
		wantErr bool
	}{
		{"/app", false},
		{"/app/bin", false},
		{"/", false},
		{"/app/../etc/passwd", true},
		{"/app/./bin", true},
		{"app/bin", true},
		{"../app", true},
		{"", true},
	}

	for _, tt := range tests {
		err := validateAbsPath(tt.path)
		if (err != nil) != tt.wantErr {
			t.Errorf("validateAbsPath(%q) error = %v, wantErr %v", tt.path, err, tt.wantErr)
		}
	}
}

func TestValidateMissingSHA256ForHTTPS(t *testing.T) {
	spec := &Spec{
		Version: "1.0",
		Contents: Contents{
			Repositories: []string{"https://packages.wolfi.dev/os"},
			Keyring:      []string{"https://packages.wolfi.dev/os/wolfi-signing.rsa.pub"},
		},
		Assets: []Asset{
			{Name: "config", Source: "https://example.com/config.json", Destination: "/etc/app/config.json"},
		},
		Runtime: Runtime{
			User:       65532,
			Workdir:    "/app",
			Entrypoint: []string{"/bin/app"},
		},
	}

	err := Validate(spec)
	if err == nil {
		t.Fatal("expected error for missing sha256 on https source")
	}
}

func TestValidateContents_MissingRequired(t *testing.T) {
	spec1 := &Spec{Version: "1.0", Contents: Contents{Keyring: []string{"k"}}} // Missing repos
	if err := validateContents(&spec1.Contents); err == nil {
		t.Error("expected error for missing repositories")
	}

	spec2 := &Spec{Version: "1.0", Contents: Contents{Repositories: []string{"r"}}} // Missing keyring
	if err := validateContents(&spec2.Contents); err == nil {
		t.Error("expected error for missing keyring")
	}
}

func TestValidateAssets_MissingFields(t *testing.T) {
	// Missing Name
	if err := validateAssets([]Asset{{Source: "local://.", Destination: "/app"}}); err == nil {
		t.Error("expected error for missing asset name")
	}
	// Missing Source
	if err := validateAssets([]Asset{{Name: "a", Destination: "/app"}}); err == nil {
		t.Error("expected error for missing asset source")
	}
	// Missing Destination
	if err := validateAssets([]Asset{{Name: "a", Source: "local://."}}); err == nil {
		t.Error("expected error for missing asset destination")
	}
	// Invalid Destination
	if err := validateAssets([]Asset{{Name: "a", Source: "local://.", Destination: "relative"}}); err == nil {
		t.Error("expected error for invalid asset destination")
	}
	// Invalid FromPath
	if err := validateAssets([]Asset{{Name: "a", Source: "local://.", Destination: "/v", FromPath: "relative"}}); err == nil {
		t.Error("expected error for invalid asset from_path")
	}
}

func TestValidatePipeline_MissingFields(t *testing.T) {
	// Missing Name
	if err := validatePipeline([]Step{{Uses: "alpine"}}); err == nil {
		t.Error("expected error for missing pipeline step name")
	}
	// Duplicate Name
	if err := validatePipeline([]Step{{Name: "a", Uses: "x", Run: []string{"r"}}, {Name: "a", Uses: "x", Run: []string{"r"}}}); err == nil {
		t.Error("expected error for duplicate pipeline step name")
	}
}

func TestValidatePipelineStep_MissingFields(t *testing.T) {
	// Missing Uses
	if err := validatePipelineStep(0, Step{Name: "a", Run: []string{"cmd"}}); err == nil {
		t.Error("expected error for missing pipeline step uses")
	}
	// Missing Run
	if err := validatePipelineStep(0, Step{Name: "a", Uses: "alpine"}); err == nil {
		t.Error("expected error for missing pipeline step run")
	}
	// Empty string in Run
	if err := validatePipelineStep(0, Step{Name: "a", Uses: "alpine", Run: []string{"cmd", "  "}}); err == nil {
		t.Error("expected error for empty command in run array")
	}
	// Invalid Workdir
	if err := validatePipelineStep(0, Step{Name: "a", Uses: "alpine", Run: []string{"cmd"}, Workdir: "relative"}); err == nil {
		t.Error("expected error for invalid pipeline step workdir")
	}
	// Invalid Mount Target
	if err := validatePipelineStep(0, Step{Name: "a", Uses: "alpine", Run: []string{"cmd"}, Mounts: []Mount{{Target: "rel"}}}); err == nil {
		t.Error("expected error for invalid mount target")
	}
	// Invalid RootfsMount
	if err := validatePipelineStep(0, Step{Name: "a", Uses: "alpine", Run: []string{"cmd"}, RootfsMount: "rel"}); err == nil {
		t.Error("expected error for invalid rootfs mount")
	}
}

func TestValidateStepExports_InvalidPaths(t *testing.T) {
	// Invalid Source
	if err := validateStepExports(0, []Export{{Source: "rel"}}); err == nil {
		t.Error("expected error for invalid export source")
	}
	// Invalid Destination
	if err := validateStepExports(0, []Export{{Source: "/tmp", Destination: "rel"}}); err == nil {
		t.Error("expected error for invalid export destination")
	}
}

func TestValidateRuntime_InvalidWorkdir(t *testing.T) {
	err := validateRuntime(&Runtime{User: 1, Workdir: "relative", Entrypoint: []string{"sh"}})
	if err == nil {
		t.Error("expected error for invalid runtime workdir")
	}
}
