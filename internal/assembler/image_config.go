package assembler

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"time"

	ocispecs "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/loganprice/mantle/pkg/config"
)

// ImageConfig holds the OCI image configuration derived from the mantle.yaml runtime spec.
type ImageConfig struct {
	// OCI is the OCI-compliant image configuration.
	OCI      ocispecs.ImageConfig
	OS, Arch string
}

// NewImageConfig builds an OCI ImageConfig from the runtime section of the spec.
func NewImageConfig(spec *config.Spec, arch string) *ImageConfig {
	rt := spec.Runtime

	env := buildEnv(rt.Env)

	cfg := ocispecs.ImageConfig{
		User:       strconv.Itoa(rt.User),
		WorkingDir: rt.Workdir,
		Entrypoint: rt.Entrypoint,
		Cmd:        rt.Args,
		Env:        env,
		Labels: map[string]string{
			"org.opencontainers.image.created": getCreationTime(),
			"io.mantle.version":                spec.Version,
			"io.mantle.shell-less":             "true",
		},
	}

	return &ImageConfig{
		OCI:  cfg,
		OS:   "linux",
		Arch: arch,
	}
}

// ToJSON serializes the ImageConfig to JSON for embedding in the BuildKit result.
func (ic *ImageConfig) ToJSON() ([]byte, error) {
	img := ocispecs.Image{
		Config: ic.OCI,
		Platform: ocispecs.Platform{
			OS:           ic.OS,
			Architecture: ic.Arch,
		},
		RootFS: ocispecs.RootFS{
			Type: "layers", // Required by OCI? Use empty. BuildKit might ignore or populate?
		},
	}
	data, err := json.Marshal(img)
	if err != nil {
		return nil, fmt.Errorf("marshaling image config: %w", err)
	}
	return data, nil
}

// buildEnv converts the mantle.yaml env map
// to OCI-format environment variables ("KEY=VALUE").
func buildEnv(envMap map[string]string) []string {
	env := make([]string, 0, len(envMap))
	for k, v := range envMap {
		env = append(env, fmt.Sprintf("%s=%s", k, v))
	}
	return env
}

// getCreationTime returns the OCI image creation time. It respects the
// SOURCE_DATE_EPOCH environment variable for reproducible builds, falling back
// to the current time if not set or invalid.
func getCreationTime() string {
	if v := os.Getenv("SOURCE_DATE_EPOCH"); v != "" {
		if sec, err := strconv.ParseInt(v, 10, 64); err == nil {
			return time.Unix(sec, 0).UTC().Format(time.RFC3339)
		}
	}
	return time.Now().UTC().Format(time.RFC3339)
}
