// Package assets implements multi-source file injection for the mantle build.
// It handles local:// (build context), oci:// (container image), and
// https:// (HTTP download) sources, converting each into an LLB state.
package assets

import (
	"fmt"
	"strings"

	"github.com/moby/buildkit/client/llb"
	"github.com/opencontainers/go-digest"

	"github.com/loganprice/mantle/pkg/config"
)

// SourceFetcher resolves assets from a specific source scheme.
type SourceFetcher interface {
	Scheme() string
	Fetch(asset config.Asset, localCtx llb.State, ref string) (llb.State, error)
}

// Fetcher resolves assets from multiple source types into LLB states.
type Fetcher struct {
	sources map[string]SourceFetcher
}

// NewFetcher creates a new multi-source asset fetcher.
func NewFetcher(ignoreCache, forcePull bool) *Fetcher {
	return &Fetcher{
		sources: map[string]SourceFetcher{
			"local": &localFetcher{ignoreCache: ignoreCache},
			"oci":   &ociFetcher{ignoreCache: ignoreCache, forcePull: forcePull},
			"https": &httpFetcher{ignoreCache: ignoreCache},
		},
	}
}

// FetchAll resolves all assets and returns one LLB state per asset.
// The localCtx state represents the build context for local:// sources.
func (f *Fetcher) FetchAll(assets []config.Asset, localCtx llb.State) ([]llb.State, error) {
	states := make([]llb.State, 0, len(assets))

	for _, asset := range assets {
		st, err := f.fetchOne(asset, localCtx)
		if err != nil {
			return nil, fmt.Errorf("asset %q: %w", asset.Name, err)
		}
		states = append(states, st)
	}

	return states, nil
}

func (f *Fetcher) fetchOne(asset config.Asset, localCtx llb.State) (llb.State, error) {
	scheme, ref := ParseSource(asset.Source)

	if fetcher, ok := f.sources[scheme]; ok {
		return fetcher.Fetch(asset, localCtx, ref)
	}

	return llb.State{}, fmt.Errorf("unsupported source scheme %q", scheme)
}

type localFetcher struct {
	ignoreCache bool
}

func (f *localFetcher) Scheme() string { return "local" }

func (f *localFetcher) Fetch(asset config.Asset, localCtx llb.State, ref string) (llb.State, error) {
	opts := []llb.CopyOption{
		&llb.CopyInfo{
			AllowWildcard:  true,
			CreateDestPath: true,
		},
	}

	result := llb.Scratch().File(
		llb.Copy(localCtx, ref, asset.Destination, opts...),
		llb.WithCustomName(fmt.Sprintf("[asset] copy local %s", asset.Name)),
	)

	return result, nil
}

type ociFetcher struct {
	ignoreCache bool
	forcePull   bool
}

func (f *ociFetcher) Scheme() string { return "oci" }

func (f *ociFetcher) Fetch(asset config.Asset, _ llb.State, ref string) (llb.State, error) {
	srcPath := asset.FromPath
	if srcPath == "" {
		srcPath = "/"
	}

	opts := []llb.ImageOption{llb.WithCustomName(fmt.Sprintf("[asset] pull %s", ref))}
	if f.ignoreCache {
		opts = append(opts, llb.IgnoreCache)
	}
	if f.forcePull {
		opts = append(opts, llb.ResolveDigest(true))
	}

	img := llb.Image(ref, opts...)

	result := llb.Scratch().File(
		llb.Copy(img, srcPath, asset.Destination, &llb.CopyInfo{
			CreateDestPath: true,
		}),
		llb.WithCustomName(fmt.Sprintf("[asset] extract %s from %s", asset.Name, ref)),
	)

	return result, nil
}

type httpFetcher struct {
	ignoreCache bool
}

func (f *httpFetcher) Scheme() string { return "https" }

func (f *httpFetcher) Fetch(asset config.Asset, _ llb.State, ref string) (llb.State, error) {
	// Reconstruct URL as `https://` was stripped by ParseSource
	url := "https://" + ref

	opts := []llb.HTTPOption{
		llb.Filename(pathBase(asset.Destination)),
		llb.WithCustomName(fmt.Sprintf("[asset] download %s", asset.Name)),
	}

	if asset.SHA256 != "" {
		opts = append(opts, llb.Checksum(digestFromSHA256(asset.SHA256)))
	}
	if f.ignoreCache {
		opts = append(opts, llb.IgnoreCache)
	}

	httpFile := llb.HTTP(url, opts...)

	// Copy the downloaded file to its final destination
	result := llb.Scratch().File(
		llb.Copy(httpFile, pathBase(asset.Destination), asset.Destination, &llb.CopyInfo{
			CreateDestPath: true,
		}),
		llb.WithCustomName(fmt.Sprintf("[asset] place %s", asset.Name)),
	)

	return result, nil
}

// ParseSource splits "scheme://ref" into (scheme, ref).
func ParseSource(source string) (scheme, ref string) {
	if strings.HasPrefix(source, "local://") {
		return "local", strings.TrimPrefix(source, "local://")
	}
	if strings.HasPrefix(source, "oci://") {
		return "oci", strings.TrimPrefix(source, "oci://")
	}
	if strings.HasPrefix(source, "https://") {
		return "https", strings.TrimPrefix(source, "https://")
	}
	return "", source
}

// pathBase extracts the last component from a path.
func pathBase(p string) string {
	parts := strings.Split(p, "/")
	for i := len(parts) - 1; i >= 0; i-- {
		if parts[i] != "" {
			return parts[i]
		}
	}
	return p
}

// digestFromSHA256 creates an OCI digest from a hex SHA256.
func digestFromSHA256(sha string) digest.Digest {
	return digest.NewDigestFromEncoded(digest.SHA256, sha)
}
