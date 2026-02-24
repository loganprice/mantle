package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"testing"

	"github.com/moby/buildkit/frontend/gateway/client"
	fstypes "github.com/tonistiigi/fsutil/types"
)

type mockClientMain struct {
	client.Client
	pemKey   []byte
	apkIndex []byte
}

func (m *mockClientMain) BuildOpts() client.BuildOpts {
	return client.BuildOpts{
		Opts: map[string]string{"platform": "linux/amd64", "no-cache": ""},
	}
}

func (m *mockClientMain) Solve(_ context.Context, _ client.SolveRequest) (*client.Result, error) {
	res := client.NewResult()
	res.SetRef(&mockReferenceMain{pemKey: m.pemKey, apkIndex: m.apkIndex})
	return res, nil
}

type mockReferenceMain struct {
	client.Reference
	pemKey   []byte
	apkIndex []byte
}

func (m *mockReferenceMain) ReadFile(_ context.Context, req client.ReadRequest) ([]byte, error) {
	// mock loadConfig reading mantle.yaml
	if req.Filename == "mantle.yaml" {
		yamlData := `version: "1.0"
contents:
  packages: ["wolfi-baselayout"]
  repositories: ["https://example.com/repo"]
  keyring: ["https://example.com/key.pub"]
runtime:
  user: 65532
  workdir: /tmp
  entrypoint: ["/bin/sh"]
`
		return []byte(yamlData), nil
	}
	if req.Filename == "key.pub" {
		return m.pemKey, nil
	}
	// mock APKINDEX tarball proxy
	if req.Filename == "APKINDEX.tar.gz" {
		return m.apkIndex, nil
	}

	return nil, fmt.Errorf("unexpected ReadFile: %s", req.Filename)
}

func (m *mockReferenceMain) ReadDir(_ context.Context, _ client.ReadDirRequest) ([]*fstypes.Stat, error) {
	return nil, nil
}
func (m *mockReferenceMain) StatFile(_ context.Context, _ client.StatRequest) (*fstypes.Stat, error) {
	return nil, nil
}

func buildTestSignedAPK(priv *rsa.PrivateKey, dataContent string) []byte {
	var dataBuf bytes.Buffer
	gw := gzip.NewWriter(&dataBuf)
	tw := tar.NewWriter(gw)
	_ = tw.WriteHeader(&tar.Header{Name: "APKINDEX", Size: int64(len(dataContent)), Mode: 0o644, Typeflag: tar.TypeReg})
	_, _ = tw.Write([]byte(dataContent))
	_ = tw.Close()
	_ = gw.Close()

	dataStream := dataBuf.Bytes()
	hash := sha1.Sum(dataStream)
	sigBytes, _ := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA1, hash[:])

	var sigBuf bytes.Buffer
	gwSig := gzip.NewWriter(&sigBuf)
	twSig := tar.NewWriter(gwSig)
	_ = twSig.WriteHeader(&tar.Header{Name: ".SIGN.RSA.key.pub", Size: int64(len(sigBytes)), Mode: 0o644, Typeflag: tar.TypeReg})
	_, _ = twSig.Write(sigBytes)
	_ = twSig.Close()
	_ = gwSig.Close()

	var finalRes []byte
	finalRes = append(finalRes, sigBuf.Bytes()...)
	finalRes = append(finalRes, dataStream...)
	return finalRes
}

func TestBuild_Success(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	pubDER, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	pemBlock := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	apkIndexBytes := buildTestSignedAPK(priv, "P:wolfi-baselayout\nV:1\n")

	mc := &mockClientMain{
		pemKey:   pemBlock,
		apkIndex: apkIndexBytes,
	}

	res, err := Build(context.Background(), mc)
	if err != nil {
		t.Fatalf("unexpected Build() execution failure mapping BuildKit nodes natively: %v", err)
	}
	if res == nil {
		t.Errorf("expected complete graph execution to export map natively")
	}
}
