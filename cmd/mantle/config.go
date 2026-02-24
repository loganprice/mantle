package main

import (
	"bytes"
	"context"
	"fmt"
	"runtime"
	"strings"
	"text/template"

	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/frontend/gateway/client"
	"gopkg.in/yaml.v3"

	"github.com/loganprice/mantle/pkg/config"
)

// loadConfig reads mantle.yaml from the build context and parses it.
func loadConfig(ctx context.Context, c client.Client, arch string) (*config.Spec, error) {
	src := llb.Local("context",
		llb.IncludePatterns([]string{"mantle.yaml"}),
		llb.WithCustomName("[mantle] read build context"),
	)

	srcDef, err := src.Marshal(ctx)
	if err != nil {
		return nil, fmt.Errorf("marshaling context request: %w", err)
	}

	srcRes, err := c.Solve(ctx, client.SolveRequest{
		Definition: srcDef.ToPB(),
	})
	if err != nil {
		return nil, fmt.Errorf("solving context request: %w", err)
	}

	srcRef, err := srcRes.SingleRef()
	if err != nil {
		return nil, fmt.Errorf("getting context reference: %w", err)
	}

	yamlData, err := srcRef.ReadFile(ctx, client.ReadRequest{
		Filename: "mantle.yaml",
	})
	if err != nil {
		return nil, fmt.Errorf("reading mantle.yaml: %w", err)
	}

	buildArgs := getBuildArgs(c)

	// Extract default args from the YAML file before full templating
	defaultArgs := extractDefaultArgs(yamlData)

	// Merge defaults with CLI args (CLI args take precedence)
	mergedArgs := make(map[string]string)
	for k, v := range defaultArgs {
		mergedArgs[k] = v
	}
	for k, v := range buildArgs {
		mergedArgs[k] = v
	}

	tplData := TemplateData{
		BuildArgs: mergedArgs,
		Arch:      arch,
		Platform:  "linux/" + arch, // BuildKit format
	}

	// Execute Go text/template
	t, err := template.New("mantle.yaml").Option("missingkey=error").Parse(string(yamlData))
	if err != nil {
		return nil, fmt.Errorf("parsing template: %w", err)
	}

	var buf bytes.Buffer
	if err := t.Execute(&buf, tplData); err != nil {
		return nil, fmt.Errorf("executing template: %w", err)
	}

	spec, err := config.Parse(buf.Bytes())
	if err != nil {
		return nil, fmt.Errorf("parsing configuration: %w\nResolved YAML:\n%s", err, buf.String())
	}

	return spec, nil
}

// TemplateData is the context object injected into mantle.yaml templates.
type TemplateData struct {
	BuildArgs map[string]string // e.g., --build-arg FOO=bar
	Arch      string            // e.g., amd64, arm64
	Platform  string            // e.g., linux/amd64
}

// getBuildArgs parses build arguments passed via the BuildKit client options.
func getBuildArgs(c client.Client) map[string]string {
	args := make(map[string]string)
	if opts := c.BuildOpts().Opts; opts != nil {
		for k, v := range opts {
			if strings.HasPrefix(k, "build-arg:") {
				argName := strings.TrimPrefix(k, "build-arg:")
				args[argName] = v
			}
		}
	}
	return args
}

// getTargetPlatforms determines the requested output architectures from BuildKit options,
// defaulting to the daemon's host architecture.
func getTargetPlatforms(c client.Client) []string {
	archs := []string{runtime.GOARCH}
	if opts := c.BuildOpts().Opts; opts != nil {
		if p, ok := opts["platform"]; ok {
			archs = []string{} // override default if platforms specified
			platforms := strings.Split(p, ",")
			for _, platform := range platforms {
				// Platform format is typically "linux/amd64" or "linux/arm64"
				parts := strings.SplitN(platform, "/", 3)
				if len(parts) >= 2 {
					archs = append(archs, parts[1])
				} else if len(parts) == 1 && parts[0] != "" {
					archs = append(archs, parts[0])
				}
			}
		}
	}
	if len(archs) == 0 {
		archs = []string{runtime.GOARCH}
	}
	return archs
}

// extractDefaultArgs performs a simple line-by-line scan of the raw YAML to find
// a top-level "args:" block and extract default key-value pairs. This allows
// defaults to be extracted even if the rest of the file contains complex template
// logic that would break a standard YAML parser before template execution.
func extractDefaultArgs(data []byte) map[string]string {
	args := make(map[string]string)
	lines := bytes.Split(data, []byte("\n"))
	var argsBlock bytes.Buffer
	inArgs := false

	for _, line := range lines {
		if !inArgs {
			if bytes.HasPrefix(line, []byte("args:")) {
				inArgs = true
				argsBlock.Write(line)
				argsBlock.WriteByte('\n')
			}
			continue
		}

		// Skip empty lines or pure comments in block
		trimmed := bytes.TrimSpace(line)
		if len(trimmed) == 0 || trimmed[0] == '#' {
			argsBlock.Write(line)
			argsBlock.WriteByte('\n')
			continue
		}

		// Exit args block if we encounter a new top-level key (no leading space)
		if len(line) > 0 && line[0] != ' ' && line[0] != '\t' && line[0] != '\r' {
			break
		}

		argsBlock.Write(line)
		argsBlock.WriteByte('\n')
	}

	if inArgs {
		var parsed struct {
			Args map[string]interface{} `yaml:"args"`
		}
		if err := yaml.Unmarshal(argsBlock.Bytes(), &parsed); err == nil && parsed.Args != nil {
			for k, v := range parsed.Args {
				if v != nil {
					args[k] = fmt.Sprintf("%v", v)
				} else {
					args[k] = ""
				}
			}
		}
	}

	return args
}
