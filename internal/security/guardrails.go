// Package security enforces hardening guardrails on the final image.
// It ensures shell-less runtime, no-root enforcement, and capability restrictions.
package security

import (
	"fmt"

	"github.com/moby/buildkit/client/llb"

	"github.com/loganprice/mantle/pkg/config"
)

// shellPaths lists shell binaries removed from production images.
var shellPaths = []string{
	"/bin/sh",
	"/bin/ash",
	"/bin/bash",
	"/bin/dash",
	"/bin/zsh",
	"/usr/bin/sh",
	"/usr/bin/bash",
	"/bin/busybox", // Alpine's default monolith binary that underpins /bin/sh
	"/sbin/apk",    // Alpine's package manager
}

// EnforceNoRoot returns an error if user 0 is configured without an explicit
// force_root override. This prevents accidental root containers.
func EnforceNoRoot(spec *config.Spec) error {
	if spec.Runtime.User == 0 && !spec.Runtime.ForceRoot {
		return fmt.Errorf(
			"security violation: runtime.user=0 (root) is not allowed; " +
				"set force_root: true to override this guardrail",
		)
	}
	return nil
}

// RemoveShells returns an LLB state with all known shell binaries removed.
// This produces a shell-less image that prevents interactive shell access.
func RemoveShells(rootfs llb.State) llb.State {
	if len(shellPaths) == 0 {
		return rootfs
	}

	action := llb.Rm(shellPaths[0], llb.WithAllowNotFound(true))
	for _, shellPath := range shellPaths[1:] {
		action = action.Rm(shellPath, llb.WithAllowNotFound(true))
	}

	return rootfs.File(
		action,
		llb.WithCustomName("[security] remove shells"),
	)
}
