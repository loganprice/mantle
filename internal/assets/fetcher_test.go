package assets

import (
	"context"
	"testing"

	"github.com/moby/buildkit/client/llb"

	"github.com/loganprice/mantle/pkg/config"
)

func TestParseSource(t *testing.T) {
	tests := []struct {
		source     string
		wantScheme string
		wantRef    string
	}{
		{"local://./src", "local", "./src"},
		{"oci://ghcr.io/org/tools:latest", "oci", "ghcr.io/org/tools:latest"},
		{"https://example.com/file.json", "https", "example.com/file.json"},
		{"ftp://unknown.com/file", "", "ftp://unknown.com/file"},
	}

	for _, tt := range tests {
		scheme, ref := ParseSource(tt.source)
		if scheme != tt.wantScheme {
			t.Errorf("ParseSource(%q) scheme = %q, want %q", tt.source, scheme, tt.wantScheme)
		}
		if ref != tt.wantRef {
			t.Errorf("ParseSource(%q) ref = %q, want %q", tt.source, ref, tt.wantRef)
		}
	}
}

func TestPathBase(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"/etc/app/config.json", "config.json"},
		{"/usr/bin/helper", "helper"},
		{"file.txt", "file.txt"},
		{"/trailing/", "trailing"},
	}

	for _, tt := range tests {
		got := pathBase(tt.input)
		if got != tt.want {
			t.Errorf("pathBase(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestDigestFromSHA256(t *testing.T) {
	hash := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	d := digestFromSHA256(hash)
	want := "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if d.String() != want {
		t.Errorf("digestFromSHA256 = %q, want %q", d.String(), want)
	}
}

func TestFetchers(t *testing.T) {
	f := NewFetcher(false, false)
	ctx := context.TODO()
	localCtx := llb.Scratch()

	tests := []struct {
		name    string
		asset   config.Asset
		wantErr bool
	}{
		{
			name: "local asset",
			asset: config.Asset{
				Name:        "local-test",
				Source:      "local://./src",
				Destination: "/src",
			},
		},
		{
			name: "oci asset",
			asset: config.Asset{
				Name:        "oci-test",
				Source:      "oci://alpine:latest",
				Destination: "/alpine",
			},
		},
		{
			name: "https asset",
			asset: config.Asset{
				Name:        "https-test",
				Source:      "https://example.com/file",
				Destination: "/file",
				SHA256:      "a38435dcfecbf6c255ec031a61ea720bdf60b5e4cfff225d3dfebbc612345678",
			},
		},
		{
			name: "unsupported scheme",
			asset: config.Asset{
				Name:   "invalid",
				Source: "ftp://example.com",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := f.fetchOne(tt.asset, localCtx)
			if (err != nil) != tt.wantErr {
				t.Fatalf("fetchOne() err = %v, wantErr %v", err, tt.wantErr)
			}

			// Marshal out to verify it returns a valid LLB state if no error
			if err == nil {
				if _, marshalErr := out.Marshal(ctx); marshalErr != nil {
					t.Errorf("unexpected error marshaling state: %v", marshalErr)
				}
			}
		})
	}
}

func TestFetchAll(t *testing.T) {
	f := NewFetcher(true, true)

	// Valid assets
	validAssets := []config.Asset{
		{Name: "a", Source: "local://.", Destination: "/a"},
		{Name: "b", Source: "oci://alpine", Destination: "/b"},
	}

	states, err := f.FetchAll(validAssets, llb.Scratch())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(states) != 2 {
		t.Errorf("expected 2 states, got %d", len(states))
	}

	// Invalid asset triggers error
	invalidAssets := []config.Asset{
		{Name: "a", Source: "local://.", Destination: "/a"},
		{Name: "bad", Source: "bad://abc", Destination: "/bad"},
	}

	_, err = f.FetchAll(invalidAssets, llb.Scratch())
	if err == nil {
		t.Fatal("expected error on unsupported scheme during FetchAll")
	}
}

func TestScheme(t *testing.T) {
	lf := &localFetcher{}
	if lf.Scheme() != "local" {
		t.Errorf("local scheme failed")
	}
	of := &ociFetcher{}
	if of.Scheme() != "oci" {
		t.Errorf("oci scheme failed")
	}
	hf := &httpFetcher{}
	if hf.Scheme() != "https" {
		t.Errorf("http scheme failed")
	}
}

func TestPathBase_Empty(t *testing.T) {
	if pb := pathBase(""); pb != "" {
		t.Errorf("expected empty string, got %q", pb)
	}
	if pb := pathBase("/"); pb != "/" {
		t.Errorf("expected /, got %q", pb)
	}
}
