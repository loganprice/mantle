package resolver

import (
	"context"

	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/frontend/gateway/client"
)

// APKFetcher defines the interface for fetching Wolfi APK data.
type APKFetcher interface {
	// FetchIndex downloads and parses the APKINDEX.
	FetchIndex(_ context.Context, c client.Client, repo string, arch string) (index []byte, pkgMap map[string][]*apkPackage, err error)

	// FetchPackage downloads an individual .apk file and returns its LLB state.
	FetchPackage(_, arch, filename string) llb.State
}

// Verifier defines the interface for verifying artifact signatures.
type Verifier interface {
	// Verify signature of the given data against the keyring.
	Verify(_ []byte, name string) error
}
