package resolver

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"strings"
	"testing"

	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/frontend/gateway/client"
	"github.com/loganprice/mantle/pkg/config"
)

func TestArchFromPlatform(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"amd64", "x86_64"},
		{"arm64", "aarch64"},
		{"riscv64", "riscv64"},
		{"unknown", "unknown"},
	}

	for _, tt := range tests {
		got := ArchFromPlatform(tt.input)
		if got != tt.expected {
			t.Errorf("ArchFromPlatform(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

// TODO: Implement mock client.Client to test Resolve method interactions

func TestResolveDependencies_DiamondConflict(t *testing.T) {
	// A -> B, C
	// B -> D
	// C -> D < 2.0
	// D has 2.0 and 1.0 (greedily picking 2.0 from B's dependency would cause C to fail later)

	mockIndex := map[string][]*apkPackage{
		"A": {{Name: "A", Version: "1.0", Dependencies: []string{"B", "C"}}},
		"B": {{Name: "B", Version: "1.0", Dependencies: []string{"D"}}},
		"C": {{Name: "C", Version: "1.0", Dependencies: []string{"D<2.0"}}},
		"D": {
			{Name: "D", Version: "2.0"},
			{Name: "D", Version: "1.0"},
		},
	}

	r := &Resolver{}
	pkgs, err := r.resolveDependencies(mockIndex, []string{"A"})
	if err != nil {
		t.Fatalf("SAT solver failed to resolve valid diamond dependency: %v", err)
	}

	foundD := false
	for _, pkg := range pkgs {
		if pkg.Name == "D" {
			foundD = true
			if pkg.Version != "1.0" {
				t.Errorf("Expected D version 1.0 to satisfy constraints, got %s", pkg.Version)
			}
		}
	}
	if !foundD {
		t.Errorf("Package D was not installed")
	}
}

func TestResolver_Options(t *testing.T) {
	mockFetch := &mockAPKFetcher{}
	mockVer := &mockVerifier{}

	r := New("amd64",
		WithFetcher(mockFetch),
		WithVerifier(mockVer),
		WithIgnoreCache(true),
		WithForcePull(true),
	)

	if r.arch != "amd64" {
		t.Errorf("expected amd64")
	}
	if r.fetcher != mockFetch {
		t.Errorf("expected mock fetcher")
	}
	if r.verifier != mockVer {
		t.Errorf("expected mock verifier")
	}

	// Test options applied to DefaultAPKFetcher fallback
	r2 := New("amd64", WithIgnoreCache(true), WithForcePull(true))
	defFetch, ok := r2.fetcher.(*DefaultAPKFetcher)
	if !ok || !defFetch.ignoreCache || !defFetch.forcePull {
		t.Errorf("expected ignoreCache and forcePull to apply to default fetcher")
	}
}

func TestParseAPKIndex_Error(t *testing.T) {
	_, err := parseAPKIndex([]byte("not a gzip"))
	if err == nil {
		t.Fatal("expected error parsing junk APKINDEX")
	}
}

func TestVirtualComponent(t *testing.T) {
	if !isVirtualComponent("so:libcrypto.so.3") {
		t.Errorf("expected true")
	}
	if isVirtualComponent("libcrypto") {
		t.Errorf("expected false")
	}
}

type mockAPKFetcher struct {
	err error
}

func (m *mockAPKFetcher) FetchIndex(ctx context.Context, c client.Client, repo string, arch string) ([]byte, map[string][]*apkPackage, error) {
	if m.err != nil {
		return nil, nil, m.err
	}
	idx := map[string][]*apkPackage{
		"base": {{Name: "base", Version: "1", Filename: "base-1.apk"}},
	}
	return []byte("raw"), idx, nil
}

func (m *mockAPKFetcher) FetchPackage(repo, arch, filename string) llb.State {
	return llb.Scratch()
}

func TestResolve_Mocked(t *testing.T) {
	r := New("amd64", WithFetcher(&mockAPKFetcher{}), WithVerifier(&mockVerifier{}))

	spec := config.Contents{
		Repositories: []string{"https://x"},
		Packages:     []string{"base"},
		Squash:       true,
	}

	state, pkgs, err := r.Resolve(context.Background(), nil, spec, nil)
	if err != nil {
		t.Fatalf("resolve failed: %v", err)
	}

	if len(pkgs) != 1 || pkgs[0].Name != "base" {
		t.Errorf("expected 1 package returned")
	}
	if state.Output() == nil {
		t.Errorf("expected valid LLB state")
	}
}

func TestResolve_Empty(t *testing.T) {
	r := New("amd64")
	state, pkgs, err := r.Resolve(context.Background(), nil, config.Contents{}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pkgs) > 0 {
		t.Errorf("expected 0 pkgs")
	}
	if state.Output() != nil {
		t.Errorf("expected scratch state to natively have nil output")
	}
}

func TestParseIndexStream(t *testing.T) {
	data := `P:base
V:1.0.0
p:so:libcrypto.so.3
D:libcrypto>1

P:libcrypto
V:2.0.0
`
	pkgs, err := parseIndexStream(strings.NewReader(data))
	if err != nil {
		t.Fatalf("unexpected error parsing index stream: %v", err)
	}

	if len(pkgs) != 2 {
		t.Errorf("expected 2 packages, got %d", len(pkgs))
	}

	if pkgs["base"][0].Version != "1.0.0" {
		t.Errorf("expected base version 1.0.0")
	}
	if pkgs["libcrypto"][0].Version != "2.0.0" {
		t.Errorf("expected libcrypto version 2.0.0")
	}
	if len(pkgs["base"][0].Dependencies) != 1 || pkgs["base"][0].Dependencies[0] != "libcrypto>1" {
		t.Errorf("expected base dependencies to contain libcrypto>1")
	}
	if len(pkgs["base"][0].Provides) != 1 || pkgs["base"][0].Provides[0] != "so:libcrypto.so.3" {
		t.Errorf("expected base provides to contain so:libcrypto.so.3")
	}
}

func TestParseAPKIndex_Valid(t *testing.T) {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	hdr := &tar.Header{
		Name: "APKINDEX",
		Mode: 0600,
		Size: int64(len("P:a\nV:1\n")),
	}
	_ = tw.WriteHeader(hdr)
	_, _ = tw.Write([]byte("P:a\nV:1\n"))
	_ = tw.Close()
	_ = gw.Close()

	pkgs, err := parseAPKIndex(buf.Bytes())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pkgs) != 1 {
		t.Errorf("expected 1 package")
	}
}

func TestSolve_Cycles(t *testing.T) {
	mockIndex := map[string][]*apkPackage{
		"A": {{Name: "A", Version: "1", Dependencies: []string{"B"}}},
		"B": {{Name: "B", Version: "1", Dependencies: []string{"A"}}},
	}

	r := &Resolver{}
	pkgs, err := r.resolveDependencies(mockIndex, []string{"A"})
	if err != nil {
		t.Fatalf("unexpected failure resolving cyclical graph natively: %v", err)
	}
	if len(pkgs) != 2 {
		t.Errorf("expected 2 packages installed safely without recursion limit")
	}
}
