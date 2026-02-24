// Package sbom generates CycloneDX 1.5 Software Bills of Materials
// by scanning the final image filesystem for installed packages and
// combining with build-time metadata from the mantle.yaml spec.
package sbom

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/loganprice/mantle/pkg/config"
)

// BOM represents the CycloneDX 1.5 top-level BOM structure.
type BOM struct {
	BOMFormat    string      `json:"bomFormat"`
	SpecVersion  string      `json:"specVersion"`
	SerialNumber string      `json:"serialNumber"`
	Version      int         `json:"version"`
	Metadata     Metadata    `json:"metadata"`
	Components   []Component `json:"components"`
}

// Metadata contains tool and timestamp information.
type Metadata struct {
	Timestamp string     `json:"timestamp"`
	Tools     []ToolInfo `json:"tools"`
}

// ToolInfo identifies the tool that generated the SBOM.
type ToolInfo struct {
	Vendor  string `json:"vendor"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Component represents an installed package, image, or asset.
type Component struct {
	Type        string              `json:"type"` // library, container, file, application
	Name        string              `json:"name"`
	Version     string              `json:"version,omitempty"`
	PURL        string              `json:"purl,omitempty"`
	Description string              `json:"description,omitempty"`
	Licenses    []LicenseEntry      `json:"licenses,omitempty"`
	ExternalRef []ExternalReference `json:"externalReferences,omitempty"`
	Properties  []Property          `json:"properties,omitempty"`
}

// LicenseEntry holds a license identifier.
type LicenseEntry struct {
	License LicenseID `json:"license"`
}

// LicenseID wraps either an SPDX ID or a license name.
type LicenseID struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

// ExternalReference links to an external resource.
type ExternalReference struct {
	Type string `json:"type"` // distribution, website, vcs, etc.
	URL  string `json:"url"`
}

// Property is a name-value pair for additional metadata.
type Property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// GenerateSBOM produces a CycloneDX 1.5 JSON SBOM from scanned components
// and build-time metadata extracted from the spec.
func GenerateSBOM(scanned []Component, spec *config.Spec) ([]byte, error) {
	components := make([]Component, 0, len(scanned)+len(spec.Pipeline)+len(spec.Assets))

	// Add filesystem-scanned components
	components = append(components, scanned...)

	// Add pipeline base images as container components
	for i := range spec.Pipeline {
		step := &spec.Pipeline[i]
		if step.Uses == "" {
			continue
		}
		components = append(components, pipelineComponent(step.Uses))
	}

	// Add assets as components
	for _, asset := range spec.Assets {
		if c, ok := assetComponent(asset); ok {
			components = append(components, c)
		}
	}

	bom := BOM{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.5",
		SerialNumber: fmt.Sprintf("urn:uuid:%s", uuid.New().String()), // TODO: Make serial number reproducible if needed
		Version:      1,
		Metadata: Metadata{
			Timestamp: getCreationTime(),
			Tools: []ToolInfo{
				{
					Vendor:  "mantle",
					Name:    "mantle",
					Version: spec.Version,
				},
			},
		},
		Components: components,
	}

	return json.MarshalIndent(bom, "", "  ")
}

// pipelineComponent creates a Component for a pipeline base image.
func pipelineComponent(imageRef string) Component {
	name, version := parseImageRef(imageRef)
	purl := fmt.Sprintf("pkg:docker/%s", strings.ReplaceAll(imageRef, ":", "@"))

	return Component{
		Type:    "container",
		Name:    name,
		Version: version,
		PURL:    purl,
		Properties: []Property{
			{Name: "mantle:source", Value: "pipeline"},
		},
	}
}

// assetComponent creates a Component for a spec asset.
func assetComponent(asset config.Asset) (Component, bool) {
	scheme, ref := parseScheme(asset.Source)

	switch scheme {
	case "oci":
		name, version := parseImageRef(ref)
		return Component{
			Type:    "container",
			Name:    name,
			Version: version,
			PURL:    fmt.Sprintf("pkg:oci/%s", strings.ReplaceAll(ref, ":", "@")),
			Properties: []Property{
				{Name: "mantle:source", Value: "asset"},
			},
		}, true
	case "https":
		return Component{
			Type: "file",
			Name: asset.Name,
			ExternalRef: []ExternalReference{
				{Type: "distribution", URL: asset.Source},
			},
			Properties: []Property{
				{Name: "mantle:source", Value: "asset"},
				{Name: "mantle:sha256", Value: asset.SHA256},
			},
		}, true
	case "local":
		return Component{
			Type: "file",
			Name: asset.Name,
			Properties: []Property{
				{Name: "mantle:source", Value: "asset"},
				{Name: "mantle:local-path", Value: ref},
			},
		}, true
	default:
		return Component{}, false
	}
}

// parseImageRef splits "python:3.12-alpine" into ("python", "3.12-alpine").
func parseImageRef(ref string) (name, version string) {
	// First split by the last slash to isolate the image name from the registry
	idxSlash := strings.LastIndex(ref, "/")
	base := ref
	prefix := ""
	if idxSlash != -1 {
		prefix = ref[:idxSlash+1]
		base = ref[idxSlash+1:]
	}

	// Now check for a tag or digest in the base name
	// Check for '@' first, as digests contain colons (e.g. @sha256:abcd...)
	if idxAt := strings.Index(base, "@"); idxAt != -1 {
		return prefix + base[:idxAt], base[idxAt+1:]
	}
	if idxColon := strings.LastIndex(base, ":"); idxColon != -1 {
		return prefix + base[:idxColon], base[idxColon+1:]
	}

	return ref, "latest"
}

// parseScheme extracts the scheme from a source URI.
func parseScheme(source string) (scheme, ref string) {
	for _, prefix := range []string{"oci://", "https://", "local://"} {
		if strings.HasPrefix(source, prefix) {
			scheme = strings.TrimSuffix(prefix, "://")
			return scheme, strings.TrimPrefix(source, prefix)
		}
	}
	return "", source
}

// getCreationTime returns the SBOM creation time. It respects the
// SOURCE_DATE_EPOCH environment variable for reproducible builds, falling back
// to the current time if not set or invalid.
func getCreationTime() string {
	if v := os.Getenv("SOURCE_DATE_EPOCH"); v != "" {
		if sec, err := strconv.ParseInt(v, 10, 64); err == nil {
			return time.Unix(sec, 0).UTC().Format(time.RFC3339)
		}
	}
	return time.Now().UTC().Format(time.RFC3339)
}
