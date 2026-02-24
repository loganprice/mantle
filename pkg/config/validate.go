package config

import (
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"
)

// Validate checks the Spec against all mantle contract rules.
func Validate(spec *Spec) error {
	if spec.Version != "1.0" {
		return fmt.Errorf("unsupported version %q, expected \"1.0\"", spec.Version)
	}

	if err := validateContents(&spec.Contents); err != nil {
		return err
	}

	if err := validateAssets(spec.Assets); err != nil {
		return err
	}

	if err := validatePipeline(spec.Pipeline); err != nil {
		return err
	}

	if err := validateRuntime(&spec.Runtime); err != nil {
		return err
	}

	return nil
}

func validateContents(c *Contents) error {
	if len(c.Repositories) == 0 {
		return fmt.Errorf("contents.repositories must not be empty")
	}
	if len(c.Keyring) == 0 {
		return fmt.Errorf("contents.keyring must not be empty")
	}
	// packages can be empty if assets provide everything
	return nil
}

func validateAssets(assets []Asset) error {
	names := make(map[string]bool)
	for i, a := range assets {
		if a.Name == "" {
			return fmt.Errorf("assets[%d].name is required", i)
		}
		if names[a.Name] {
			return fmt.Errorf("duplicate asset name %q", a.Name)
		}
		names[a.Name] = true

		if a.Source == "" {
			return fmt.Errorf("assets[%d].source is required", i)
		}
		if err := validateAssetSource(a.Source); err != nil {
			return fmt.Errorf("assets[%d].source: %w", i, err)
		}
		if strings.HasPrefix(a.Source, "local://") {
			ref := strings.TrimPrefix(a.Source, "local://")
			cleaned := filepath.Clean(ref)
			if strings.HasPrefix(cleaned, "..") {
				return fmt.Errorf("assets[%d].source: local path %q must not traverse upwards", i, ref)
			}
		}

		if a.Destination == "" {
			return fmt.Errorf("assets[%d].destination is required", i)
		}
		if err := validateAbsPath(a.Destination); err != nil {
			return fmt.Errorf("assets[%d].destination: %w", i, err)
		}
		if a.FromPath != "" {
			if err := validateAbsPath(a.FromPath); err != nil {
				return fmt.Errorf("assets[%d].from_path: %w", i, err)
			}
		}

		if a.SHA256 != "" {
			if err := validateSHA256(a.SHA256); err != nil {
				return fmt.Errorf("assets[%d].sha256: %w", i, err)
			}
		} else if strings.HasPrefix(a.Source, "https://") {
			return fmt.Errorf("assets[%d].sha256 is required for https:// sources", i)
		}
	}
	return nil
}

// validateAssetSource checks that the source uses a known scheme.
func validateAssetSource(source string) error {
	validPrefixes := []string{"local://", "oci://", "https://"}
	for _, p := range validPrefixes {
		if strings.HasPrefix(source, p) {
			return nil
		}
	}
	return fmt.Errorf("source %q must use local://, oci://, or https:// scheme", source)
}

func validateSHA256(hash string) error {
	if len(hash) != 64 {
		return fmt.Errorf("sha256 hash must be 64 hex characters, got %d", len(hash))
	}
	if _, err := hex.DecodeString(hash); err != nil {
		return fmt.Errorf("sha256 hash is not valid hex: %w", err)
	}
	return nil
}

func validateAbsPath(p string) error {
	if !filepath.IsAbs(p) {
		return fmt.Errorf("path %q must be absolute", p)
	}
	if filepath.Clean(p) != p {
		return fmt.Errorf("path %q must be clean (do not use . or ..)", p)
	}
	return nil
}

func validatePipeline(steps []Step) error {
	names := make(map[string]bool)
	for i := range steps {
		s := steps[i]
		if s.Name == "" {
			return fmt.Errorf("pipeline[%d].name is required", i)
		}
		if names[s.Name] {
			return fmt.Errorf("duplicate pipeline step name %q", s.Name)
		}
		names[s.Name] = true

		if err := validatePipelineStep(i, s); err != nil {
			return err
		}
	}
	return nil
}

func validatePipelineStep(i int, s Step) error {
	if s.Uses == "" {
		return fmt.Errorf("pipeline[%d].uses is required", i)
	}
	if len(s.Run) == 0 {
		return fmt.Errorf("pipeline[%d].run is required", i)
	}
	for j, cmd := range s.Run {
		if strings.TrimSpace(cmd) == "" {
			return fmt.Errorf("pipeline[%d].run[%d] must not be empty", i, j)
		}
	}
	if s.Workdir != "" {
		if err := validateAbsPath(s.Workdir); err != nil {
			return fmt.Errorf("pipeline[%d].workdir: %w", i, err)
		}
	}
	for j, m := range s.Mounts {
		if err := validateAbsPath(m.Target); err != nil {
			return fmt.Errorf("pipeline[%d].mounts[%d].target: %w", i, j, err)
		}
		if m.Type == MountTypeSecret && m.Source == "" {
			return fmt.Errorf("pipeline[%d].mounts[%d].source is required for secret mounts", i, j)
		}
	}
	if err := validateStepExports(i, s.Exports); err != nil {
		return err
	}
	if s.RootfsMount != "" {
		if err := validateAbsPath(s.RootfsMount); err != nil {
			return fmt.Errorf("pipeline[%d].rootfs_mount: %w", i, err)
		}
	}
	return nil
}

func validateStepExports(stepIdx int, exports []Export) error {
	if len(exports) == 0 {
		return fmt.Errorf("pipeline[%d].exports must not be empty", stepIdx)
	}
	for j, e := range exports {
		if err := validateAbsPath(e.Source); err != nil {
			return fmt.Errorf("pipeline[%d].exports[%d].source: %w", stepIdx, j, err)
		}
		if e.Destination != "" {
			if err := validateAbsPath(e.Destination); err != nil {
				return fmt.Errorf("pipeline[%d].exports[%d].destination: %w", stepIdx, j, err)
			}
		}
	}
	return nil
}

func validateRuntime(r *Runtime) error {
	if r.User == 0 && !r.ForceRoot {
		return fmt.Errorf("runtime.user=0 (root) is not allowed; set force_root: true to override")
	}
	if r.Workdir == "" {
		return fmt.Errorf("runtime.workdir is required")
	}
	if err := validateAbsPath(r.Workdir); err != nil {
		return fmt.Errorf("runtime.workdir: %w", err)
	}
	if len(r.Entrypoint) == 0 {
		return fmt.Errorf("runtime.entrypoint is required")
	}
	return nil
}
