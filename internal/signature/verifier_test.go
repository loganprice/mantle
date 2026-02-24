package signature

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"testing"

	"github.com/moby/buildkit/frontend/gateway/client"
)

func TestAddKey(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	pemBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubDER,
	})

	kr := NewKeyring()

	// Valid key
	if err := kr.AddKey("test.rsa.pub", pemBlock); err != nil {
		t.Fatalf("AddKey failed: %v", err)
	}
	if kr.Get("test.rsa.pub") == nil {
		t.Fatal("key not found after AddKey")
	}

	// Invalid PEM
	if err := kr.AddKey("bad", []byte("not pem")); err == nil {
		t.Fatal("expected error for invalid PEM")
	}
}

func TestFindKey(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	pubDER, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	pemBlock := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	kr := NewKeyring()
	_ = kr.AddKey("wolfi-signing.rsa.pub", pemBlock)

	// Exact match via .SIGN.RSA prefix
	if kr.FindKey(".SIGN.RSA.wolfi-signing.rsa.pub") == nil {
		t.Fatal("FindKey should match .SIGN.RSA. prefix")
	}

	// Suffix match
	if kr.FindKey("some-prefix.wolfi-signing.rsa.pub") == nil {
		t.Fatal("FindKey should match by suffix")
	}

	// No match
	if kr.FindKey(".SIGN.RSA.unknown.rsa.pub") != nil {
		t.Fatal("FindKey should return nil for unknown key")
	}
}

func TestSplitGzipStreams(t *testing.T) {
	// Create two gzip streams concatenated
	var buf bytes.Buffer

	gz1 := gzip.NewWriter(&buf)
	_, _ = gz1.Write([]byte("stream one"))
	_ = gz1.Close()

	gz2 := gzip.NewWriter(&buf)
	_, _ = gz2.Write([]byte("stream two"))
	_ = gz2.Close()

	streams, err := SplitGzipStreams(buf.Bytes())
	if err != nil {
		t.Fatalf("SplitGzipStreams failed: %v", err)
	}
	if len(streams) != 2 {
		t.Fatalf("expected 2 streams, got %d", len(streams))
	}

	// Verify each stream decompresses correctly
	for i, expected := range []string{"stream one", "stream two"} {
		gzr, _ := gzip.NewReader(bytes.NewReader(streams[i]))
		data, _ := io.ReadAll(gzr)
		_ = gzr.Close()
		if string(data) != expected {
			t.Errorf("stream %d: got %q, want %q", i, string(data), expected)
		}
	}
}

func TestSplitGzipStreams_SingleStream(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	_, _ = gz.Write([]byte("only one"))
	_ = gz.Close()

	streams, err := SplitGzipStreams(buf.Bytes())
	if err != nil {
		t.Fatalf("SplitGzipStreams failed: %v", err)
	}
	if len(streams) != 1 {
		t.Fatalf("expected 1 stream, got %d", len(streams))
	}
}

func TestSplitGzipStreams_Invalid(t *testing.T) {
	// Not gzip magic
	if _, err := SplitGzipStreams([]byte("not gzip data")); err == nil {
		t.Fatal("expected error for missing gzip magic bytes")
	}

	// Corrupted gzip stream
	badGz := []byte{0x1f, 0x8b, 0x01, 0x02, 0x03}
	if _, err := SplitGzipStreams(badGz); err == nil {
		t.Fatal("expected error for corrupted gzip stream decompression")
	}
}

// buildSignedAPK creates a minimal signed APK-like multi-gzip-stream file
// for testing with SHA1. Stream 1 = signature tar, Stream 2 = data.
func buildSignedAPK(t *testing.T, priv *rsa.PrivateKey, keyName string, data []byte) []byte {
	return buildSignedAPKWithAlgo(t, priv, keyName, data, ".SIGN.RSA.", crypto.SHA1)
}

// buildSignedAPKWithAlgo creates a signed APK with a specific prefix and hash algorithm.
func buildSignedAPKWithAlgo(t *testing.T, priv *rsa.PrivateKey, keyName string, data []byte, prefix string, hashAlgo crypto.Hash) []byte {
	t.Helper()

	// Stream 2: the signed content (a gzip stream)
	var dataStream bytes.Buffer
	gz2 := gzip.NewWriter(&dataStream)
	_, _ = gz2.Write(data)
	_ = gz2.Close()
	signedBytes := dataStream.Bytes()

	// Hash and sign the raw gzip bytes of stream 2
	var hashValue []byte
	switch hashAlgo {
	case crypto.SHA256:
		h := sha256.Sum256(signedBytes)
		hashValue = h[:]
	case crypto.SHA1:
		h := sha1.Sum(signedBytes)
		hashValue = h[:]
	}
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, hashAlgo, hashValue)
	if err != nil {
		t.Fatalf("signing: %v", err)
	}

	// Stream 1: signature tar containing <prefix><keyname>
	var sigStream bytes.Buffer
	gz1 := gzip.NewWriter(&sigStream)
	tw := newTarWriter(gz1)
	writeTarEntry(t, tw, prefix+keyName, sig)
	tw.Close()
	_ = gz1.Close()

	// Concatenate: sig stream + data stream
	var result bytes.Buffer
	result.Write(sigStream.Bytes())
	result.Write(signedBytes)
	return result.Bytes()
}

func TestVerifyAPK_Valid(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	pubDER, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	pemBlock := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	kr := NewKeyring()
	_ = kr.AddKey("test.rsa.pub", pemBlock)

	apkData := buildSignedAPK(t, priv, "test.rsa.pub", []byte("package content"))

	if err := VerifyAPK(kr, apkData, "test.apk"); err != nil {
		t.Fatalf("VerifyAPK should pass for valid SHA1 signature: %v", err)
	}
}

func TestVerifyAPK_InvalidStreams(t *testing.T) {
	kr := NewKeyring()

	// Only 1 stream (missing signature)
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	_, _ = gz.Write([]byte("data only"))
	_ = gz.Close()

	if err := VerifyAPK(kr, buf.Bytes(), "bad.apk"); err == nil {
		t.Fatal("expected error when APK has fewer than 2 gzip streams")
	}

	// Corrupted internal signature tar
	var buf2 bytes.Buffer
	gz1 := gzip.NewWriter(&buf2)
	_, _ = gz1.Write([]byte("not a tar file"))
	_ = gz1.Close()
	gz2 := gzip.NewWriter(&buf2)
	_, _ = gz2.Write([]byte("data"))
	_ = gz2.Close()

	if err := VerifyAPK(kr, buf2.Bytes(), "bad-tar.apk"); err == nil {
		t.Fatal("expected error when signature stream is not a valid tar")
	}
}

func TestVerifyAPK_SHA256(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	pubDER, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	pemBlock := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	kr := NewKeyring()
	_ = kr.AddKey("wolfi-signing.rsa.pub", pemBlock)

	// Use .SIGN.RSA256. prefix + SHA256 (Wolfi format)
	apkData := buildSignedAPKWithAlgo(t, priv, "wolfi-signing.rsa.pub", []byte("wolfi package"), ".SIGN.RSA256.", crypto.SHA256)

	if err := VerifyAPK(kr, apkData, "wolfi-pkg.apk"); err != nil {
		t.Fatalf("VerifyAPK should pass for valid SHA256 signature: %v", err)
	}
}

func TestVerifyAPK_Tampered(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	pubDER, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	pemBlock := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	kr := NewKeyring()
	_ = kr.AddKey("test.rsa.pub", pemBlock)

	apkData := buildSignedAPK(t, priv, "test.rsa.pub", []byte("package content"))

	// Tamper with the data stream (last byte)
	apkData[len(apkData)-1] ^= 0xff

	if err := VerifyAPK(kr, apkData, "test.apk"); err == nil {
		t.Fatal("VerifyAPK should fail for tampered data")
	}
}

func TestVerifyAPK_WrongKey(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	wrongPriv, _ := rsa.GenerateKey(rand.Reader, 2048)

	// Keyring has the wrong key
	pubDER, _ := x509.MarshalPKIXPublicKey(&wrongPriv.PublicKey)
	pemBlock := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	kr := NewKeyring()
	_ = kr.AddKey("test.rsa.pub", pemBlock)

	// APK was signed with the correct key
	apkData := buildSignedAPK(t, priv, "test.rsa.pub", []byte("package content"))

	if err := VerifyAPK(kr, apkData, "test.apk"); err == nil {
		t.Fatal("VerifyAPK should fail with wrong key")
	}
}

// --- tar helpers ---

func newTarWriter(w interface{ Write([]byte) (int, error) }) *tarWriter {
	return &tarWriter{w: w}
}

type tarWriter struct {
	w interface{ Write([]byte) (int, error) }
}

func writeTarEntry(t *testing.T, tw *tarWriter, name string, data []byte) {
	t.Helper()
	// Minimal tar entry: 512-byte header + data blocks
	header := make([]byte, 512)
	copy(header[0:], name)
	// Size field at offset 124, 12 bytes, octal, null-terminated
	sizeStr := []byte(octal(len(data)))
	copy(header[124:], sizeStr)
	// Compute checksum
	fillChecksum(header)

	_, _ = tw.w.Write(header)
	_, _ = tw.w.Write(data)
	// Pad to 512 boundary
	if pad := 512 - (len(data) % 512); pad < 512 {
		_, _ = tw.w.Write(make([]byte, pad))
	}
}

func (tw *tarWriter) Close() {
	// Two 512-byte blocks of zeros to end tar
	_, _ = tw.w.Write(make([]byte, 1024))
}

func octal(n int) string {
	return padOctal(n, 11) + "\x00"
}

func padOctal(n, width int) string {
	s := ""
	for n > 0 {
		s = string(rune('0'+n%8)) + s
		n /= 8
	}
	if s == "" {
		s = "0"
	}
	for len(s) < width {
		s = "0" + s
	}
	return s
}

func fillChecksum(header []byte) {
	// Fill checksum field (offset 148, 8 bytes) with spaces first
	for i := 148; i < 156; i++ {
		header[i] = ' '
	}
	// Sum all bytes
	var sum int
	for _, b := range header {
		sum += int(b)
	}
	// Write checksum as 6-digit octal + null + space
	cs := padOctal(sum, 6) + "\x00 "
	copy(header[148:], cs)
}

// --- Mocking BuildKit for FetchKeyring ---

type mockClient struct {
	client.Client
	expectedPEM []byte
	expectErr   error
}

func (m *mockClient) Solve(ctx context.Context, req client.SolveRequest) (*client.Result, error) {
	if m.expectErr != nil {
		return nil, m.expectErr
	}
	res := client.NewResult()
	res.SetRef(&mockReference{pem: m.expectedPEM})
	return res, nil
}

type mockReference struct {
	client.Reference
	pem []byte
}

func (m *mockReference) ReadFile(ctx context.Context, req client.ReadRequest) ([]byte, error) {
	if req.Filename != "wolfi-signing.rsa.pub" {
		return nil, fmt.Errorf("unexpected file request: %s", req.Filename)
	}
	return m.pem, nil
}

func TestFetchKeyring(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	pubDER, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	pemBlock := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	mc := &mockClient{expectedPEM: pemBlock}

	kr, err := FetchKeyring(context.Background(), mc, []string{"https://packages.wolfi.dev/os/wolfi-signing.rsa.pub"})
	if err != nil {
		t.Fatalf("FetchKeyring failed: %v", err)
	}

	key := kr.Get("wolfi-signing.rsa.pub")
	if key == nil {
		t.Fatal("expected key to be populated in keyring")
	}

	// Test Solve error
	mcErr := &mockClient{expectErr: fmt.Errorf("solve timeout")}
	_, err = FetchKeyring(context.Background(), mcErr, []string{"https://packages.wolfi.dev/os/wolfi-signing.rsa.pub"})
	if err == nil {
		t.Fatal("expected error on solve failure")
	}

	// Test invalid PEM returned
	mcBad := &mockClient{expectedPEM: []byte("invalid pem sequence")}
	_, err = FetchKeyring(context.Background(), mcBad, []string{"https://packages.wolfi.dev/os/wolfi-signing.rsa.pub"})
	if err == nil {
		t.Fatal("expected error on invalid pem parse")
	}
}
