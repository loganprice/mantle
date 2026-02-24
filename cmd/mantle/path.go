package main

import (
	"context"
	"log/slog"
	"path"
	"sort"
	"strings"

	"github.com/moby/buildkit/frontend/gateway/client"

	"github.com/loganprice/mantle/internal/assembler"
)

// autoConfigurePATH scans the solved rootfs for bin/ directories not on the
// default PATH and prepends them to the image config. Skips if the user
// already set PATH in runtime.env.
func autoConfigurePATH(ctx context.Context, ref client.Reference, cfg *assembler.ImageConfig) {
	// Check if user already set PATH
	for _, envVar := range cfg.OCI.Env {
		if strings.HasPrefix(envVar, "PATH=") {
			return
		}
	}

	defaultPATH := "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	defaultDirs := map[string]bool{
		"/usr/local/sbin": true,
		"/usr/local/bin":  true,
		"/usr/sbin":       true,
		"/usr/bin":        true,
		"/sbin":           true,
		"/bin":            true,
	}

	var discovered []string
	for _, root := range []string{"/usr/lib", "/opt"} {
		walkForBinDirs(ctx, ref, root, 0, 3, defaultDirs, &discovered)
	}

	if len(discovered) == 0 {
		// Always set a default PATH even if no extra dirs found
		cfg.OCI.Env = append(cfg.OCI.Env, "PATH="+defaultPATH)
		return
	}

	sort.Strings(discovered)
	autoPath := strings.Join(discovered, ":") + ":" + defaultPATH
	cfg.OCI.Env = append(cfg.OCI.Env, "PATH="+autoPath)
	slog.Info("[mantle] Auto-discovered PATH", slog.String("path", autoPath))
}

// walkForBinDirs recursively scans for directories named "bin" under the
// given root, up to maxDepth levels deep.
func walkForBinDirs(ctx context.Context, ref client.Reference, dir string, depth, maxDepth int, exclude map[string]bool, result *[]string) {
	if depth > maxDepth {
		return
	}

	entries, err := ref.ReadDir(ctx, client.ReadDirRequest{Path: dir})
	if err != nil {
		return
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		fullPath := path.Join(dir, entry.GetPath())

		if entry.GetPath() == "bin" && !exclude[fullPath] {
			*result = append(*result, fullPath)
			continue
		}

		// Recurse into non-bin subdirectories
		walkForBinDirs(ctx, ref, fullPath, depth+1, maxDepth, exclude, result)
	}
}
