// Package signature verifies APK package and index signatures.
//
// APK files (both APKINDEX.tar.gz and .apk packages) use a multi-gzip-stream
// format where the first stream contains an RSA signature over the second:
//
//	Stream 1: tar with ".SIGN.RSA.<keyname>" entry (DER signature bytes)
//	Stream 2: the signed content (control data for packages, index for APKINDEX)
//
// The signature is PKCS1v15-RSA over SHA1 of Stream 2's raw gzip bytes.
package signature

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"strings"

	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/frontend/gateway/client"
)

// Keyring holds parsed RSA public keys keyed by filename.
type Keyring struct {
	keys map[string]*rsa.PublicKey
}

// NewKeyring creates an empty keyring.
func NewKeyring() *Keyring {
	return &Keyring{keys: make(map[string]*rsa.PublicKey)}
}

// AddKey adds a PEM-encoded RSA public key to the keyring under the given name.
func (k *Keyring) AddKey(name string, pemData []byte) error {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return fmt.Errorf("no PEM block found in key %q", name)
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("parsing public key %q: %w", name, err)
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("key %q is not an RSA public key", name)
	}

	k.keys[name] = rsaPub
	return nil
}

// Get returns the RSA public key for the given name, or nil if not found.
func (k *Keyring) Get(name string) *rsa.PublicKey {
	return k.keys[name]
}

// FindKey searches for a key matching the given signature entry name.
// APK signatures reference keys as ".SIGN.RSA.<keyname>" or
// ".SIGN.RSA256.<keyname>" — this method strips the prefix and finds
// the matching key.
func (k *Keyring) FindKey(sigName string) *rsa.PublicKey {
	// Strip known prefixes to get the key name
	keyName := sigName
	for _, prefix := range []string{".SIGN.RSA256.", ".SIGN.RSA."} {
		if strings.HasPrefix(sigName, prefix) {
			keyName = strings.TrimPrefix(sigName, prefix)
			break
		}
	}
	if key, ok := k.keys[keyName]; ok {
		return key
	}
	// Fallback: try matching by any key name suffix
	for name, key := range k.keys {
		if strings.HasSuffix(sigName, name) {
			return key
		}
	}
	return nil
}

// FetchKeyring downloads public key files from the given URLs and returns
// a populated Keyring. Keys are fetched via BuildKit's LLB HTTP solver.
func FetchKeyring(ctx context.Context, c client.Client, urls []string) (*Keyring, error) {
	keyring := NewKeyring()

	for _, url := range urls {
		// Extract key filename from URL (e.g. "wolfi-signing.rsa.pub")
		parts := strings.Split(url, "/")
		filename := parts[len(parts)-1]

		st := llb.HTTP(url,
			llb.Filename(filename),
			llb.WithCustomName(fmt.Sprintf("[keyring] fetch %s", filename)),
		)

		def, err := st.Marshal(ctx)
		if err != nil {
			return nil, fmt.Errorf("marshaling keyring fetch for %s: %w", filename, err)
		}

		res, err := c.Solve(ctx, client.SolveRequest{
			Definition: def.ToPB(),
		})
		if err != nil {
			return nil, fmt.Errorf("fetching keyring key %s: %w", filename, err)
		}

		ref, err := res.SingleRef()
		if err != nil {
			return nil, fmt.Errorf("getting ref for key %s: %w", filename, err)
		}

		pemData, err := ref.ReadFile(ctx, client.ReadRequest{
			Filename: filename,
		})
		if err != nil {
			return nil, fmt.Errorf("reading key file %s: %w", filename, err)
		}

		if err := keyring.AddKey(filename, pemData); err != nil {
			return nil, err
		}
		slog.Info("[keyring] loaded key",
			slog.String("filename", filename),
			slog.Int("bytes", len(pemData)))
	}

	return keyring, nil
}

// VerifyAPK verifies the signature of an APK file (APKINDEX or .apk package).
// The raw bytes must contain the complete multi-gzip-stream file.
// Supports both .SIGN.RSA. (SHA1, Alpine) and .SIGN.RSA256. (SHA256, Wolfi).
// Returns nil if verification succeeds, or an error describing the failure.
func VerifyAPK(keyring *Keyring, rawData []byte, name string) error {
	streams, err := SplitGzipStreams(rawData)
	if err != nil {
		return fmt.Errorf("splitting gzip streams for %s: %w", name, err)
	}

	if len(streams) < 2 {
		return fmt.Errorf("APK %s has %d gzip streams, expected at least 2 (signature + data)", name, len(streams))
	}

	// Stream 0 = signature tar, Stream 1 = signed content
	sigStream := streams[0]
	signedData := streams[1]

	// Extract the signature entry from the signature stream
	sigName, sigBytes, hashAlgo, err := extractSignature(sigStream)
	if err != nil {
		return fmt.Errorf("extracting signature from %s: %w", name, err)
	}

	// Find the matching public key
	pubKey := keyring.FindKey(sigName)
	if pubKey == nil {
		return fmt.Errorf("no key in keyring matches signature %q for %s", sigName, name)
	}

	// Hash the signed data with the appropriate algorithm
	var hashValue []byte
	switch hashAlgo {
	case crypto.SHA256:
		h := sha256.Sum256(signedData)
		hashValue = h[:]
	case crypto.SHA1:
		h := sha1.Sum(signedData)
		hashValue = h[:]
	default:
		return fmt.Errorf("unsupported hash algorithm for %s", name)
	}

	// Verify PKCS1v15 RSA signature
	if err := rsa.VerifyPKCS1v15(pubKey, hashAlgo, hashValue, sigBytes); err != nil {
		return fmt.Errorf("signature verification failed for %s: %w", name, err)
	}

	slog.Info("[signature] verified",
		slog.String("name", name),
		slog.String("key", sigName),
		slog.Any("algo", hashAlgo))
	return nil
}

// extractSignature reads the signature tar stream and returns the key name,
// raw DER signature bytes, and the hash algorithm to use for verification.
// Supports both .SIGN.RSA. (SHA1) and .SIGN.RSA256. (SHA256) signatures.
func extractSignature(sigStream []byte) (name string, sig []byte, hash crypto.Hash, err error) {
	gzr, err := gzip.NewReader(bytes.NewReader(sigStream))
	if err != nil {
		return "", nil, 0, fmt.Errorf("decompressing signature stream: %w", err)
	}
	defer func() { _ = gzr.Close() }()

	tr := tar.NewReader(gzr)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", nil, 0, fmt.Errorf("reading signature tar: %w", err)
		}

		var hashAlgo crypto.Hash
		switch {
		case strings.HasPrefix(header.Name, ".SIGN.RSA256."):
			hashAlgo = crypto.SHA256
		case strings.HasPrefix(header.Name, ".SIGN.RSA."):
			hashAlgo = crypto.SHA1
		default:
			continue
		}

		// Prevent OOM from maliciously large or corrupted signature blocks
		const maxSignatureSize = 2 * 1024 * 1024 // 2MB limit
		lr := io.LimitReader(tr, maxSignatureSize+1)

		sigBytes, err := io.ReadAll(lr)
		if err != nil {
			return "", nil, 0, fmt.Errorf("reading signature bytes: %w", err)
		}
		if len(sigBytes) > maxSignatureSize {
			return "", nil, 0, fmt.Errorf("signature entry exceeds maximum allowed size of 2MB")
		}

		return header.Name, sigBytes, hashAlgo, nil
	}

	return "", nil, 0, fmt.Errorf("no .SIGN.RSA.* or .SIGN.RSA256.* entry found in signature stream")
}

// SplitGzipStreams splits a concatenated multi-gzip-stream file into
// individual raw gzip stream byte slices.
//
// APK files concatenate multiple gzip streams. Go's gzip.Reader, when using
// Reset(), can read them sequentially, but we need the raw bytes of each
// stream for signature verification. This function finds gzip boundaries
// by looking for gzip magic bytes (0x1f, 0x8b) and validating each candidate.
func SplitGzipStreams(data []byte) ([][]byte, error) {
	var streams [][]byte
	offset := 0

	for offset < len(data) {
		// Each gzip stream starts with magic bytes 0x1f 0x8b
		if data[offset] != 0x1f || data[offset+1] != 0x8b {
			return nil, fmt.Errorf("expected gzip magic at offset %d, got 0x%02x 0x%02x", offset, data[offset], data[offset+1])
		}

		// Decompress this stream to find where it ends
		reader := bytes.NewReader(data[offset:])
		gzr, err := gzip.NewReader(reader)
		if err != nil {
			return nil, fmt.Errorf("creating gzip reader at offset %d: %w", offset, err)
		}
		// Critical: disable multistream so the reader stops at this stream's end
		gzr.Multistream(false)

		// Read all decompressed data to advance the reader past this stream
		// Use a LimitReader to prevent unbounded CPU exhaustion (gzip bombs)
		// Max allowed size is 2GB per stream
		const maxDecompressionSize = 2 * 1024 * 1024 * 1024
		lr := io.LimitReader(gzr, maxDecompressionSize+1)

		written, err := io.Copy(io.Discard, lr)
		if err != nil {
			_ = gzr.Close()
			return nil, fmt.Errorf("reading gzip stream at offset %d: %w", offset, err)
		}
		if written > maxDecompressionSize {
			_ = gzr.Close()
			return nil, fmt.Errorf("gzip stream at offset %d exceeds maximum decompression size of 2GB", offset)
		}
		_ = gzr.Close()

		// The bytes.Reader position tells us where this stream ended
		consumed := len(data[offset:]) - reader.Len()
		streams = append(streams, data[offset:offset+consumed])
		offset += consumed
	}

	return streams, nil
}
