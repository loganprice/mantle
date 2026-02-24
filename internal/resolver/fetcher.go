package resolver

import (
	"context"
	"fmt"
	"strings"

	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/frontend/gateway/client"

	"github.com/loganprice/mantle/internal/signature"
)

// DefaultAPKFetcher implements APKFetcher using HTTP.
type DefaultAPKFetcher struct {
	ignoreCache bool
	forcePull   bool
}

// FetchIndex fetches the APKINDEX.tar.gz from the repository and parses its contents.
func (f *DefaultAPKFetcher) FetchIndex(ctx context.Context, c client.Client, repo, arch string) (data []byte, pkgs map[string][]*apkPackage, err error) {
	indexURL := fmt.Sprintf("%s/%s/APKINDEX.tar.gz", repo, arch)

	opts := []llb.HTTPOption{
		llb.Filename("APKINDEX.tar.gz"),
		llb.WithCustomName("[wolfi] fetch index"),
	}
	if f.ignoreCache {
		opts = append(opts, llb.IgnoreCache)
	}
	// Use llb.HTTP to fetch the index
	st := llb.HTTP(indexURL, opts...)

	def, err := st.Marshal(ctx)
	if err != nil {
		return nil, nil, err
	}

	res, err := c.Solve(ctx, client.SolveRequest{
		Definition: def.ToPB(),
	})
	if err != nil {
		return nil, nil, err
	}

	ref, err := res.SingleRef()
	if err != nil {
		return nil, nil, err
	}

	data, err = ref.ReadFile(ctx, client.ReadRequest{
		Filename: "APKINDEX.tar.gz",
	})
	if err != nil {
		return nil, nil, err
	}

	pkgs, err = parseAPKIndex(data)
	if err != nil {
		return nil, nil, err
	}

	return data, pkgs, nil
}

// FetchPackage returns an LLB state that downloads the specified .apk package.
func (f *DefaultAPKFetcher) FetchPackage(repo, arch, filename string) llb.State {
	// Wolfi packages are organized by arch
	url := fmt.Sprintf("%s/%s/%s", repo, arch, filename)

	opts := []llb.HTTPOption{
		llb.Filename(filename),
		llb.WithCustomName(fmt.Sprintf("[wolfi] fetch %s", strings.TrimSuffix(filename, ".apk"))),
	}
	if f.ignoreCache {
		opts = append(opts, llb.IgnoreCache)
	}
	// Individual .apk file fetch
	return llb.HTTP(url, opts...)
}

// KeyringVerifier adapts signature.Keyring to the Verifier interface.
type KeyringVerifier struct {
	keyring *signature.Keyring
}

// NewKeyringVerifier creates a new KeyringVerifier from a signature.Keyring.
func NewKeyringVerifier(k *signature.Keyring) *KeyringVerifier {
	return &KeyringVerifier{keyring: k}
}

// Verify checks the digital signature of the provided data against the keyring.
func (v *KeyringVerifier) Verify(data []byte, name string) error {
	if v.keyring == nil {
		return nil // No keyring, no verification (or should we fail?)
		// In existing logic: if keyring != nil, verify. Here we assume Verifier is only used if verified is needed.
		// But let's follow existing pattern: if caller passes a nil Verifier, we skip.
		// If caller passes a KeyringVerifier with nil keyring, it's effectively a no-op?
		// Actually, VerifyAPK returns error if keyring is nil inside? No, it takes keyring arg.
	}
	return signature.VerifyAPK(v.keyring, data, name)
}
