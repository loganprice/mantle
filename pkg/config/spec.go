// Package config provides types and parsing for the mantle.yaml specification.
// The mantle.yaml file is the single source of truth that replaces a traditional
// Dockerfile with a declarative security contract.
package config

// Spec constants defining magic strings across the schema.
const (
	MountTypeCache  = "cache"
	MountTypeSecret = "secret"
	MountTypeSSH    = "ssh"
	DefaultWorkdir  = "/work"
)

// Spec is the top-level mantle.yaml specification.
type Spec struct {
	Version  string            `yaml:"version"`
	Args     map[string]string `yaml:"args,omitempty"`
	Contents Contents          `yaml:"contents"`
	Assets   []Asset           `yaml:"assets,omitempty"`
	Pipeline []Step            `yaml:"pipeline,omitempty"`
	Runtime  Runtime           `yaml:"runtime"`
}

// Contents defines the Wolfi package layer.
type Contents struct {
	Repositories []string `yaml:"repositories"`
	Keyring      []string `yaml:"keyring"`
	Packages     []string `yaml:"packages"`
	Squash       bool     `yaml:"squash,omitempty"`
}

// Asset defines a single file or directory to inject from an external source.
type Asset struct {
	Name        string `yaml:"name"`
	Source      string `yaml:"source"`
	Destination string `yaml:"destination"`
	FromPath    string `yaml:"from_path,omitempty"`
	UID         int    `yaml:"uid,omitempty"`
	GID         int    `yaml:"gid,omitempty"`
	SHA256      string `yaml:"sha256,omitempty"`
}

// Step defines an ephemeral build stage in the pipeline.
type Step struct {
	Name        string            `yaml:"name"`
	Uses        string            `yaml:"uses"`
	Run         []string          `yaml:"run"`               // Commands to execute sequentially in the step's environment
	Env         map[string]string `yaml:"env,omitempty"`     // Environment variables for the step
	Workdir     string            `yaml:"workdir,omitempty"` // Writable working directory; copies rootfs here
	Mounts      []Mount           `yaml:"mounts,omitempty"`
	Exports     []Export          `yaml:"exports"`
	RootfsMount string            `yaml:"rootfs_mount,omitempty"` // Default: /work (legacy read-only mount)
}

// Export defines a path to extract from a pipeline step into the final image.
// Simple form: "/install" (source = destination)
// Full form:   source: /install, destination: /usr/local
type Export struct {
	Source      string `yaml:"source"`
	Destination string `yaml:"destination,omitempty"`
}

// UnmarshalYAML allows Export to be specified as either a plain string
// ("/install") or a mapping ({source: /install, destination: /usr/local}).
func (e *Export) UnmarshalYAML(unmarshal func(interface{}) error) error {
	// Try plain string first
	var s string
	if err := unmarshal(&s); err == nil {
		e.Source = s
		e.Destination = s
		return nil
	}

	// Fall back to struct
	type exportAlias Export // avoid recursion
	var alias exportAlias
	if err := unmarshal(&alias); err != nil {
		return err
	}
	*e = Export(alias)
	if e.Destination == "" {
		e.Destination = e.Source
	}
	return nil
}

// Mount defines a mount for a pipeline step.
type Mount struct {
	Type   string `yaml:"type"`
	Target string `yaml:"target"`
	Source string `yaml:"source"`
}

// Runtime defines the final image configuration and hardening rules.
type Runtime struct {
	User       int               `yaml:"user"`
	Workdir    string            `yaml:"workdir"`
	Entrypoint []string          `yaml:"entrypoint"`
	Args       []string          `yaml:"args,omitempty"`
	Env        map[string]string `yaml:"env,omitempty"`

	ForceRoot bool            `yaml:"force_root,omitempty"`
	Options   *RuntimeOptions `yaml:"options,omitempty"`
}

// RuntimeOptions allows for precise opt-outs of hardening rules.
type RuntimeOptions struct {
	RemoveShells *bool `yaml:"remove_shells,omitempty"`
}
