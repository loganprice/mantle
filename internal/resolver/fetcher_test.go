package resolver

import (
	"context"
	"fmt"
	"testing"

	"github.com/moby/buildkit/frontend/gateway/client"
)

type mockClient struct {
	client.Client
	expectedData []byte
	expectErr    error
}

func (m *mockClient) Solve(_ context.Context, _ client.SolveRequest) (*client.Result, error) {
	if m.expectErr != nil {
		return nil, m.expectErr
	}
	res := client.NewResult()
	res.SetRef(&mockReference{data: m.expectedData})
	return res, nil
}

type mockReference struct {
	client.Reference
	data []byte
}

func (m *mockReference) ReadFile(_ context.Context, req client.ReadRequest) ([]byte, error) {
	if req.Filename != "APKINDEX.tar.gz" {
		return nil, fmt.Errorf("unexpected file request: %s", req.Filename)
	}
	return m.data, nil
}

func TestFetchIndex(t *testing.T) {
	mc := &mockClient{expectedData: []byte("mock tarball")}
	f := &DefaultAPKFetcher{ignoreCache: true, forcePull: true}

	raw, _, err := f.FetchIndex(context.Background(), mc, "https://example.com/repo", "x86_64")
	if err == nil {
		t.Fatal("expected error parsing invalid APKINDEX tarball")
	}
	if raw != nil {
		t.Errorf("expected no raw data on index validation failure")
	}

	mcErr := &mockClient{expectErr: fmt.Errorf("solve fail")}
	_, _, err = f.FetchIndex(context.Background(), mcErr, "https://example.com/repo", "x86_64")
	if err == nil {
		t.Fatal("expected error from upstream solve failure")
	}
}

func TestFetchPackage(t *testing.T) {
	f := &DefaultAPKFetcher{}
	state := f.FetchPackage("https://example.com/repo", "arm64", "foo-1.0.apk")
	if state.Output() == nil {
		t.Fatalf("expected valid llb state representing the package download")
	}
}

type mockVerifier struct {
	err error
}

func (m *mockVerifier) Verify(_ []byte, _ string) error {
	return m.err
}

func TestNewKeyringVerifier(t *testing.T) {
	v := NewKeyringVerifier(nil)
	if v == nil {
		t.Fatal("expected KeyringVerifier to be constructed")
	}
	err := v.Verify([]byte("data"), "test")
	if err != nil {
		t.Fatalf("expected nil error (skip) when verifying with nil keyring, got: %v", err)
	}
}
