// Package resolver constructs LLB states for Wolfi APK package installation.
// It downloads APKINDEX data and .apk files via BuildKit's llb.HTTP,
// unpacking them directly into a rootfs layer without requiring a local apk binary.
package resolver

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"log/slog"
	"sort"
	"strings"

	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/frontend/gateway/client"

	"github.com/loganprice/mantle/internal/signature"
	"github.com/loganprice/mantle/pkg/config"
)

// PackageInfo holds metadata about a resolved package for SBOM generation.
type PackageInfo struct {
	Name    string
	Version string
	Arch    string
	URL     string
}

// Resolver builds LLB states that install Wolfi APK packages.
type Resolver struct {
	arch     string
	fetcher  APKFetcher
	verifier Verifier
}

// Option defines a functional option for configuring the Resolver.
type Option func(*Resolver)

// WithFetcher sets a custom APKFetcher.
func WithFetcher(f APKFetcher) Option {
	return func(r *Resolver) {
		r.fetcher = f
	}
}

// WithVerifier sets a custom Verifier.
func WithVerifier(v Verifier) Option {
	return func(r *Resolver) {
		r.verifier = v
	}
}

// WithIgnoreCache enables bypassing the BuildKit cache for external calls.
func WithIgnoreCache(ignoreCache bool) Option {
	return func(r *Resolver) {
		if def, ok := r.fetcher.(*DefaultAPKFetcher); ok {
			def.ignoreCache = ignoreCache
		}
	}
}

// WithForcePull enables active tag resolution via llb.ResolveDigest(true).
func WithForcePull(forcePull bool) Option {
	return func(r *Resolver) {
		if def, ok := r.fetcher.(*DefaultAPKFetcher); ok {
			def.forcePull = forcePull
		}
	}
}

// New creates a Resolver for the given architecture.
func New(arch string, opts ...Option) *Resolver {
	r := &Resolver{
		arch:    arch,
		fetcher: &DefaultAPKFetcher{},
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// Resolve constructs an LLB state containing all requested Wolfi packages
// and their dependencies.
func (r *Resolver) Resolve(ctx context.Context, c client.Client, contents config.Contents, keyring *signature.Keyring) (llb.State, []PackageInfo, error) {
	if len(contents.Repositories) == 0 {
		return llb.Scratch(), nil, nil
	}

	// Configure verifier if keyring is provided and no verifier is set
	// (or always prefer keyring?)
	// If the user provided a custom verifier via Options, we should use it.
	// If r.verifier is nil, we create one from keyring.
	verifier := r.verifier
	if verifier == nil && keyring != nil {
		verifier = NewKeyringVerifier(keyring)
	}

	// 1. Fetch APKINDEX from the first repository
	repo := strings.TrimSuffix(contents.Repositories[0], "/")
	slog.Info("[wolfi] Fetching index", slog.String("repo", repo))

	rawIndex, index, err := r.fetcher.FetchIndex(ctx, c, repo, r.arch)
	if err != nil {
		return llb.State{}, nil, fmt.Errorf("fetching index: %w", err)
	}

	// 1a. Verify APKINDEX signature
	if verifier != nil {
		if err := verifier.Verify(rawIndex, "APKINDEX.tar.gz"); err != nil {
			return llb.State{}, nil, fmt.Errorf("APKINDEX signature verification: %w", err)
		}
	}

	// Count unique package names for logging
	slog.Info("[wolfi] Index parsed", slog.Int("unique_packages", len(index)))

	// 2. Resolve dependencies
	resolvedPkgs, err := r.resolveDependencies(index, contents.Packages)
	if err != nil {
		return llb.State{}, nil, fmt.Errorf("resolving dependencies: %w", err)
	}
	slog.Info("[wolfi] Dependencies resolved", slog.Int("resolved_packages", len(resolvedPkgs)))

	// 3. Construct LLB — fetch, verify, and unpack each package
	layers := make([]llb.State, 0, len(resolvedPkgs))
	pkgs := make([]PackageInfo, 0, len(resolvedPkgs))

	for _, pkg := range resolvedPkgs {
		apkURL := fmt.Sprintf("%s/%s/%s", repo, r.arch, pkg.Filename)

		// Fetch the .apk file using the fetcher interface
		apkFile := r.fetcher.FetchPackage(repo, r.arch, pkg.Filename)

		unpack := llb.Image("alpine:3.20@sha256:a4f4213abb84c497377b8544c81b3564f313746700372ec4fe84653e4fb03805", llb.WithCustomName("[wolfi] unpack base")).
			Run(
				llb.Args([]string{"tar", "xzf", "/tmp/" + pkg.Filename, "-C", "/dest"}),
				llb.WithCustomName(fmt.Sprintf("[wolfi] unpack %s", pkg.Name)),
				llb.AddMount("/tmp/"+pkg.Filename, apkFile, llb.SourcePath(pkg.Filename)),
				llb.AddMount("/dest", llb.Scratch()),
			).
			GetMount("/dest")

		layers = append(layers, unpack)
		pkgs = append(pkgs, PackageInfo{
			Name:    pkg.Name,
			Version: pkg.Version,
			Arch:    r.arch,
			URL:     apkURL,
		})
	}

	merged := llb.Merge(layers, llb.WithCustomName("[wolfi] merge packages"))

	if contents.Squash {
		squashed := llb.Scratch().File(
			llb.Copy(merged, "/", "/", &llb.CopyInfo{
				CopyDirContentsOnly: true,
				CreateDestPath:      true,
			}),
			llb.WithCustomName("[wolfi] squash packages"),
		)
		merged = squashed
	}

	return merged, pkgs, nil
}

// apkPackage represents an entry in APKINDEX.
type apkPackage struct {
	Name         string
	Version      string
	Filename     string
	Dependencies []string
	Provides     []string
}

// parseAPKIndex parses the APKINDEX and returns a map of package names to versions.
func parseAPKIndex(data []byte) (map[string][]*apkPackage, error) {
	streams, _ := signature.SplitGzipStreams(data)
	if len(streams) == 0 {
		streams = [][]byte{data}
	}

	for _, streamBytes := range streams {
		gzr, err := gzip.NewReader(bytes.NewReader(streamBytes))
		if err != nil {
			continue
		}

		tr := tar.NewReader(gzr)
		for {
			header, err := tr.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				continue
			}
			if header.Name == "APKINDEX" {
				res, err := parseIndexStream(tr)
				gzr.Close()
				return res, err
			}
		}
		gzr.Close()
	}
	return nil, fmt.Errorf("APKINDEX not found in archive")
}

func parseIndexStream(r io.Reader) (map[string][]*apkPackage, error) {
	pkgs := make(map[string][]*apkPackage)
	scanner := bufio.NewScanner(r)
	// Wolfi APKINDEX can be very large; increase the buffer
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var current *apkPackage

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			if current != nil && current.Name != "" {
				current.Filename = fmt.Sprintf("%s-%s.apk", current.Name, current.Version)
				pkgs[current.Name] = append(pkgs[current.Name], current)
			}
			current = nil
			continue
		}

		if len(line) < 2 || line[1] != ':' {
			continue
		}

		key := line[0]
		val := line[2:]

		if current == nil {
			current = &apkPackage{}
		}

		switch key {
		case 'P':
			current.Name = val
		case 'V':
			current.Version = val
		case 'D':
			current.Dependencies = strings.Fields(val)
		case 'p':
			current.Provides = strings.Fields(val)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading APKINDEX: %w", err)
	}

	// Handle last entry
	if current != nil && current.Name != "" {
		current.Filename = fmt.Sprintf("%s-%s.apk", current.Name, current.Version)
		pkgs[current.Name] = append(pkgs[current.Name], current)
	}

	return pkgs, nil
}

// resolveState tracks the current SAT branch constraints
type resolveState struct {
	index    map[string][]*apkPackage
	provides map[string]string
	selected map[string]*apkPackage
	visited  map[string]bool
}

// resolveDependencies performs transitive dependency resolution using a SAT-style
// recursive backtracking search.
func (r *Resolver) resolveDependencies(index map[string][]*apkPackage, roots []string) ([]*apkPackage, error) {
	state := &resolveState{
		index:    index,
		provides: buildProvidesMap(index),
		selected: make(map[string]*apkPackage),
		visited:  make(map[string]bool),
	}

	queue := make([]string, 0, len(roots))

	// Pre-process roots for explicit exclusions
	for _, req := range roots {
		name, _, _ := ParseDependency(req)
		if strings.HasPrefix(name, "!") {
			excludedPkg := strings.TrimPrefix(name, "!")
			state.visited[excludedPkg] = true
			slog.Info("[wolfi] Excluding package explicitly", slog.String("package", excludedPkg))
		} else {
			queue = append(queue, req)
		}
	}

	if ok := r.solve(state, queue, 0); !ok {
		return nil, fmt.Errorf("could not resolve a satisfying dependency graph Native constraints conflicted")
	}

	result := make([]*apkPackage, 0, len(state.selected))
	for _, pkg := range state.selected {
		result = append(result, pkg)
	}
	return result, nil
}

// solve is the recursive backtracking SAT solver engine.
func (r *Resolver) solve(state *resolveState, queue []string, depth int) bool {
	if len(queue) == 0 {
		return true // Terminated cleanly: all dependencies satisfied!
	}

	if depth > 5000 {
		slog.Error("[wolfi] SAT resolution exceeded max recursion limit (possible cycle)")
		return false
	}

	req := queue[0]
	nextQueue := queue[1:]

	name, op, ver := ParseDependency(req)

	// Negated deps were pre-processed or ignored transitively
	if strings.HasPrefix(name, "!") {
		return r.solve(state, nextQueue, depth+1)
	}

	// Resolve provider mapped aliases natively
	pkgName := name
	if provider, ok := state.provides[name]; ok {
		pkgName = provider
	}

	// If physically excluded, this branch hits a dead end
	if state.visited[pkgName] && state.selected[pkgName] == nil {
		return false
	}

	// Is it already installed in this branch?
	if existing, ok := state.selected[pkgName]; ok {
		// Does the already-picked version satisfy this specific new constraint?
		if op != "" && !MatchConstraint(existing.Version, op+ver) {
			return false // BACKTRACK: Existing selection conflicts with downstream strict constraint
		}
		// It satisfies it natively. Move to the next dependency.
		return r.solve(state, nextQueue, depth+1)
	}

	candidates, ok := state.index[pkgName]
	if !ok {
		// Virtual components (so:, cmd:, pc:) are silently ignored if unresolved
		if isVirtualComponent(name) {
			return r.solve(state, nextQueue, depth+1)
		}
		slog.Warn("[wolfi] Target package not found in index, skipping natively", slog.String("package", name))
		return r.solve(state, nextQueue, depth+1)
	}

	validCandidates := getValidCandidates(candidates, op, ver)

	for _, candidate := range validCandidates {
		// Attempt branch natively
		state.selected[pkgName] = candidate

		// Push nested transitive dependencies
		branchQueue := append([]string{}, nextQueue...)
		branchQueue = append(branchQueue, candidate.Dependencies...)

		if r.solve(state, branchQueue, depth+1) {
			return true // Found a valid sub-graph!
		}

		// Backtrack: this version ultimately caused a conflict below. Try the next older valid candidate.
		delete(state.selected, pkgName)
	}

	// Exhausted all candidates internally, graph constraints are fundamentally unsat down this rootfs path.
	return false
}

func getValidCandidates(candidates []*apkPackage, op, ver string) []*apkPackage {
	var valid []*apkPackage
	for _, pkg := range candidates {
		if op == "" || MatchConstraint(pkg.Version, op+ver) {
			valid = append(valid, pkg)
		}
	}
	sort.Slice(valid, func(i, j int) bool {
		return CompareVersions(valid[i].Version, valid[j].Version) > 0
	})
	return valid
}

func isVirtualComponent(name string) bool {
	return strings.HasPrefix(name, "so:") || strings.HasPrefix(name, "cmd:") || strings.HasPrefix(name, "pc:")
}

// ArchFromPlatform converts an OCI platform architecture string to the
// APK architecture identifier.
func ArchFromPlatform(platform string) string {
	switch platform {
	case "amd64":
		return "x86_64"
	case "arm64":
		return "aarch64"
	default:
		return platform
	}
}

// buildProvidesMap creates a mapping of virtual packages to real package names
func buildProvidesMap(index map[string][]*apkPackage) map[string]string {
	provides := make(map[string]string)
	for name := range index {
		provides[name] = name // package provides itself
		if len(index[name]) > 0 {
			// Quick newest find for provides
			newestPkg := index[name][0]
			for _, pkg := range index[name][1:] {
				if CompareVersions(pkg.Version, newestPkg.Version) > 0 {
					newestPkg = pkg
				}
			}
			for _, p := range newestPkg.Provides {
				pname, _, _ := ParseDependency(p)
				if _, exists := provides[pname]; !exists {
					provides[pname] = name
				}
			}
		}
	}
	return provides
}
