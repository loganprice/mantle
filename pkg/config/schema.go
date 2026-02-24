package config

import (
	_ "embed"
	"fmt"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v5"
	"gopkg.in/yaml.v3"
)

//go:embed fixtures/schema.json
var schemaJSON string

var (
	compiledSchema *jsonschema.Schema
	schemaErr      error
	schemaOnce     sync.Once
)

// ValidateSchema validates the YAML node against the embedded JSON schema.
func ValidateSchema(node *yaml.Node) error {
	schemaOnce.Do(func() {
		compiler := jsonschema.NewCompiler()
		if err := compiler.AddResource("schema.json", strings.NewReader(schemaJSON)); err != nil {
			schemaErr = fmt.Errorf("parsing embedded schema: %w", err)
			return
		}
		compiledSchema, schemaErr = compiler.Compile("schema.json")
		if schemaErr != nil {
			schemaErr = fmt.Errorf("compiling schema: %w", schemaErr)
		}
	})

	if schemaErr != nil {
		return schemaErr
	}

	// Convert YAML Node to JSON structure (map[string]interface{})
	// because jsonschema expects standard Go types (map[string]interface{}, []interface{}, etc.)
	// compatible with encoding/json.
	var obj interface{}
	if err := node.Decode(&obj); err != nil {
		return fmt.Errorf("decoding yaml node for validation: %w", err)
	}

	// Make sure keys are strings (yaml.v3 can produce map[interface{}]interface{})
	// For simple YAML configs, it usually works, but complex keys might be an issue.
	// However, json schema validation libraries often handle this or we need to sanitize.
	// Let's assume standard YAML with string keys.
	// Actually, santhosh-tekuri/jsonschema supports validation of Go structs/maps directly if they are JSON-compatible.
	// But maps from yaml.Unmarshal might be map[string]interface{} or map[interface{}]interface{}.
	// We might need to ensure map keys are strings.
	var normErr error
	obj, normErr = normalizeYAML(obj)
	if normErr != nil {
		return fmt.Errorf("normalizing yaml: %w", normErr)
	}

	if err := compiledSchema.Validate(obj); err != nil {
		return fmt.Errorf("schema validation failed: %w", err)
	}

	return nil
}

// normalizeYAML converts map[interface{}]interface{} to map[string]interface{}
func normalizeYAML(i interface{}) (interface{}, error) {
	switch x := i.(type) {
	case map[interface{}]interface{}:
		m2 := map[string]interface{}{}
		for k, v := range x {
			ks, ok := k.(string)
			if !ok {
				return nil, fmt.Errorf("non-string key found in YAML: %v", k)
			}
			v2, err := normalizeYAML(v)
			if err != nil {
				return nil, err
			}
			m2[ks] = v2
		}
		return m2, nil
	case map[string]interface{}:
		for k, v := range x {
			v2, err := normalizeYAML(v)
			if err != nil {
				return nil, err
			}
			x[k] = v2
		}
		return x, nil
	case []interface{}:
		for i, v := range x {
			v2, err := normalizeYAML(v)
			if err != nil {
				return nil, err
			}
			x[i] = v2
		}
		return x, nil
	}
	return i, nil
}
