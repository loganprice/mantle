package config

import (
	"bytes"
	"fmt"

	"gopkg.in/yaml.v3"
)

// Parse deserializes raw YAML bytes into a validated Spec.
// It strips the leading '# syntax=' directive if present.
func Parse(data []byte) (*Spec, error) {
	cleaned := stripSyntaxDirective(data)

	var node yaml.Node
	if err := yaml.Unmarshal(cleaned, &node); err != nil {
		return nil, fmt.Errorf("parsing yaml: %w", err)
	}

	// Validate against JSON schema first
	if err := ValidateSchema(&node); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	var spec Spec
	if err := node.Decode(&spec); err != nil {
		return nil, fmt.Errorf("decoding yaml: %w", err)
	}

	if spec.Version == "" {
		return nil, fmt.Errorf("missing version field")
	}

	if err := Validate(&spec); err != nil {
		return nil, fmt.Errorf("validating mantle.yaml: %w", err)
	}

	return &spec, nil
}

// stripSyntaxDirective removes the '# syntax=...' line that BuildKit
// uses to identify the frontend image. This is not part of the YAML spec.
func stripSyntaxDirective(data []byte) []byte {
	lines := bytes.SplitN(data, []byte("\n"), 2)
	if len(lines) > 0 && bytes.HasPrefix(bytes.TrimSpace(lines[0]), []byte("# syntax=")) {
		if len(lines) > 1 {
			return lines[1]
		}
		return nil
	}
	return data
}
