// Package pipeline handles ephemeral build stages that produce artifacts
// without leaking build tools into the final image. It uses llb.Diff to
// extract only the exported paths from each transient build step.
package pipeline

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"

	"github.com/moby/buildkit/client/llb"

	"github.com/loganprice/mantle/pkg/config"
)

// Processor converts pipeline steps into LLB diff-extracted states.
type Processor struct {
	ignoreCache bool
	forcePull   bool
}

// NewProcessor creates a new pipeline Processor.
func NewProcessor(ignoreCache, forcePull bool) *Processor {
	return &Processor{ignoreCache: ignoreCache, forcePull: forcePull}
}

// Process converts each pipeline step into an LLB state containing only
// the exported paths. Build tools in the transient image are discarded.
//
// The diff-copy approach:
//  1. Snapshot the base image state
//  2. Run the build command (pip install, npm install, etc.)
//  3. llb.Diff(before, after) captures only new files
//  4. llb.Copy the exported paths to a clean scratch layer
func (p *Processor) Process(steps []config.Step, rootfs llb.State) ([]llb.State, error) {
	exports := make([]llb.State, 0, len(steps))

	for i := range steps {
		st := p.processStep(steps[i], rootfs)
		exports = append(exports, st)
	}

	return exports, nil
}

func (p *Processor) processStep(step config.Step, rootfs llb.State) llb.State {
	// Start with the transient build image
	opts := []llb.ImageOption{
		llb.WithCustomName(fmt.Sprintf("[pipeline] base %s", step.Name)),
	}
	if p.forcePull {
		opts = append(opts, llb.ResolveDigest(true))
	}
	base := llb.Image(step.Uses, opts...)

	// Build base run options
	baseRunOpts := make([]llb.RunOption, 0, 1+len(step.Env))

	runState := base
	workdirState := rootfs // Tracks the mutable state of the mounted workdir

	if step.Workdir != "" {
		// Workdir mode: natively mount the rootfs. This avoids massive
		// llb.Copy I/O bottlenecks by utilizing overlay mounts directly.
		baseRunOpts = append(baseRunOpts, llb.Dir(step.Workdir))
	} else {
		// Legacy mode: mount rootfs read-only at mount point
		mountPoint := step.RootfsMount
		if mountPoint == "" {
			mountPoint = config.DefaultWorkdir
		}
		baseRunOpts = append(baseRunOpts, llb.AddMount(mountPoint, rootfs, llb.Readonly))
	}

	// Inject environment variables (sorted for deterministic builds)
	for _, key := range sortedKeys(step.Env) {
		baseRunOpts = append(baseRunOpts, llb.AddEnv(key, step.Env[key]))
	}

	var lastRun llb.ExecState
	for i, cmd := range step.Run {
		cmdOpts := append([]llb.RunOption{}, baseRunOpts...)

		// Bind the current workdir state to the execution
		if step.Workdir != "" {
			cmdOpts = append(cmdOpts, llb.AddMount(step.Workdir, workdirState))
		}

		cmdOpts = append(cmdOpts,
			llb.Args([]string{"/bin/sh", "-c", cmd}),
			llb.WithCustomName(fmt.Sprintf("[pipeline] run %s (%d/%d)", step.Name, i+1, len(step.Run))),
		)

		// Add cache and secret mounts natively as RunOptions
		for _, mount := range step.Mounts {
			if mount.Type == config.MountTypeCache {
				cmdOpts = append(cmdOpts, llb.AddMount(mount.Target, llb.Scratch(),
					llb.AsPersistentCacheDir(
						sanitizeCacheID(step.Name, mount.Target),
						llb.CacheMountShared,
					),
				))
			} else if mount.Type == config.MountTypeSecret {
				cmdOpts = append(cmdOpts, llb.AddSecret(mount.Target, llb.SecretID(mount.Source)))
			}
		}

		if p.ignoreCache {
			cmdOpts = append(cmdOpts, llb.IgnoreCache)
		}

		lastRun = runState.Run(cmdOpts...)

		// Capture the mutated state of the workdir after the run
		if step.Workdir != "" {
			workdirState = lastRun.GetMount(step.Workdir)
		}
		runState = lastRun.Root()
	}

	// Compute the diff: only new files from the run step
	var diff llb.State
	if step.Workdir != "" {
		// 1. Changes made to the container (outside of the workdir)
		rootDiff := llb.Diff(base, runState,
			llb.WithCustomName(fmt.Sprintf("[pipeline] diff root %s", step.Name)),
		)

		// 2. Changes made natively to the mounted rootfs
		mountDiff := llb.Diff(rootfs, workdirState,
			llb.WithCustomName(fmt.Sprintf("[pipeline] diff mount %s", step.Name)),
		)

		// Combine paths declaratively to avoid undefined merge behavior on overlap.
		// We copy the mutated mount files explicitly over the root changes.
		diff = rootDiff.File(
			llb.Copy(mountDiff, "/", step.Workdir, &llb.CopyInfo{
				CreateDestPath:      true,
				CopyDirContentsOnly: true,
			}),
			llb.WithCustomName(fmt.Sprintf("[pipeline] merge diffs %s", step.Name)),
		)
	} else {
		diff = llb.Diff(base, runState,
			llb.WithCustomName(fmt.Sprintf("[pipeline] diff %s", step.Name)),
		)
	}

	// Extract only the exported paths into a clean scratch layer
	result := llb.Scratch()
	for _, export := range step.Exports {
		result = result.File(
			llb.Copy(diff, export.Source, export.Destination, &llb.CopyInfo{
				CreateDestPath:     true,
				AllowWildcard:      true,
				AllowEmptyWildcard: true,
			}),
			llb.WithCustomName(fmt.Sprintf("[pipeline] export %s:%s→%s", step.Name, export.Source, export.Destination)),
		)
	}

	return result
}

// sanitizeCacheID creates a stable cache mount identifier from step name and target.
// It uses a SHA256 hash to prevent collision vulnerabilities between similar path structures.
func sanitizeCacheID(stepName, target string) string {
	hash := sha256.Sum256([]byte(fmt.Sprintf("%s-%s", stepName, target)))
	return "mantle-" + hex.EncodeToString(hash[:])
}

// sortedKeys returns map keys in sorted order for deterministic iteration.
func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
