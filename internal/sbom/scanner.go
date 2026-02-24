package sbom

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"debug/buildinfo"
	"encoding/json"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"

	"github.com/moby/buildkit/frontend/gateway/client"
	fstypes "github.com/tonistiigi/fsutil/types"

	"github.com/loganprice/mantle/internal/resolver"
)

// EcosystemScanner defines the interface for language-specific package scanners.
type EcosystemScanner interface {
	Name() string
	Scan(ctx context.Context, ref client.Reference) []Component
}

// Scanner discovers installed packages in the final image filesystem.
type Scanner struct {
	scanners []EcosystemScanner
}

// NewScanner creates a Scanner with all registered ecosystem scanners.
func NewScanner() *Scanner {
	return &Scanner{
		scanners: []EcosystemScanner{
			&pythonScanner{},
			&nodeScanner{},
			&goScanner{},
			&javaScanner{},
			&dotnetScanner{},
		},
	}
}

// Scan reads the image filesystem via the BuildKit ref and returns
// all discovered components. pkgInfos from the resolver is used to
// enrich APK components with download URLs.
func (s *Scanner) Scan(ctx context.Context, ref client.Reference, pkgInfos []resolver.PackageInfo) []Component {
	var components []Component

	// Build lookup map from resolver data
	pkgLookup := make(map[string]resolver.PackageInfo, len(pkgInfos))
	for _, pi := range pkgInfos {
		key := pi.Name + "=" + pi.Version
		pkgLookup[key] = pi
	}

	// Scan APK database (base OS packages)
	if apkComps, err := scanAPK(ctx, ref, pkgLookup); err == nil {
		components = append(components, apkComps...)
		slog.Info("[sbom] Found APK packages", slog.Int("count", len(apkComps)))
	} else {
		slog.Error("[sbom] APK scan error", slog.String("error", err.Error()))
	}

	// Run all registered ecosystem scanners
	for _, scanner := range s.scanners {
		if comps := scanner.Scan(ctx, ref); len(comps) > 0 {
			components = append(components, comps...)
			slog.Info("[sbom] Found packages",
				slog.Int("count", len(comps)),
				slog.String("ecosystem", scanner.Name()))
		}
	}

	return components
}

// scanAPK parses /lib/apk/db/installed to discover APK packages.
// Cross-references with pkgLookup to enrich components with download URLs.
func scanAPK(ctx context.Context, ref client.Reference, pkgLookup map[string]resolver.PackageInfo) ([]Component, error) {
	data, err := ref.ReadFile(ctx, client.ReadRequest{
		Filename: "/lib/apk/db/installed",
	})
	if err != nil {
		return nil, fmt.Errorf("reading APK database: %w", err)
	}

	return parseAPKDatabase(string(data), pkgLookup), nil
}

// parseAPKDatabase parses the APK installed database text.
// Each package is separated by a blank line.
// Fields: P=name, V=version, A=arch, T=description, L=license, U=url.
func parseAPKDatabase(data string, pkgLookup map[string]resolver.PackageInfo) []Component {
	var components []Component
	scanner := bufio.NewScanner(strings.NewReader(data))

	current := &apkPackage{}

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			if comp := current.toComponent(pkgLookup); comp != nil {
				components = append(components, *comp)
			}
			current = &apkPackage{}
			continue
		}
		current.parseLine(line)
	}

	if comp := current.toComponent(pkgLookup); comp != nil {
		components = append(components, *comp)
	}

	return components
}

type apkPackage struct {
	Name, Version, Arch, Desc, License, URL string
}

func (p *apkPackage) parseLine(line string) {
	if len(line) < 2 || line[1] != ':' {
		return
	}
	field, value := line[0], line[2:]
	switch field {
	case 'P':
		p.Name = value
	case 'V':
		p.Version = value
	case 'A':
		p.Arch = value
	case 'T':
		p.Desc = value
	case 'L':
		p.License = value
	case 'U':
		p.URL = value
	}
}

func (p *apkPackage) toComponent(pkgLookup map[string]resolver.PackageInfo) *Component {
	if p.Name == "" {
		return nil
	}

	purl := fmt.Sprintf("pkg:apk/wolfi/%s@%s", p.Name, p.Version)
	if p.Arch != "" {
		purl += "?arch=" + p.Arch
	}

	comp := Component{
		Type:    "library",
		Name:    p.Name,
		Version: p.Version,
		PURL:    purl,
		Properties: []Property{
			{Name: "mantle:source", Value: "apk"},
			{Name: "mantle:ecosystem", Value: "wolfi"},
		},
	}

	if p.Desc != "" {
		comp.Description = p.Desc
	}

	if p.License != "" {
		comp.Licenses = []LicenseEntry{
			{License: LicenseID{Name: p.License}},
		}
	}

	// Cross-check with resolver data for enrichment
	key := p.Name + "=" + p.Version
	if pi, ok := pkgLookup[key]; ok {
		if pi.URL != "" {
			comp.ExternalRef = []ExternalReference{
				{Type: "distribution", URL: pi.URL},
			}
		}
		comp.Properties = append(comp.Properties,
			Property{Name: "mantle:verified", Value: "true"},
		)
	} else if p.URL != "" {
		comp.ExternalRef = []ExternalReference{
			{Type: "website", URL: p.URL},
		}
	}

	return &comp
}

type pythonScanner struct{}

func (s *pythonScanner) Name() string { return "python" }

// Scan finds Python packages by reading .dist-info/METADATA files
// from common site-packages directories.
func (s *pythonScanner) Scan(ctx context.Context, ref client.Reference) []Component {
	// Search common Python site-packages paths
	searchPaths := []string{
		"/usr/lib",
		"/usr/local/lib",
		"/install/lib",
	}

	var components []Component
	seen := make(map[string]bool)

	for _, base := range searchPaths {
		pyDirs, err := safeReadDir(ctx, ref, base)
		if err != nil {
			continue
		}

		for _, pyDir := range pyDirs {
			if !pyDir.IsDir() || !strings.HasPrefix(pyDir.GetPath(), "python") {
				continue
			}

			sitePackages := filepath.Join(base, pyDir.GetPath(), "site-packages")
			distInfos, err := safeReadDir(ctx, ref, sitePackages)
			if err != nil {
				continue
			}

			for _, di := range distInfos {
				if !di.IsDir() || !strings.HasSuffix(di.GetPath(), ".dist-info") {
					continue
				}

				metadataPath := filepath.Join(sitePackages, di.GetPath(), "METADATA")
				data, err := ref.ReadFile(ctx, client.ReadRequest{Filename: metadataPath})
				if err != nil {
					continue
				}

				comp := parsePythonMetadata(string(data))
				if comp.Name != "" && !seen[comp.Name] {
					seen[comp.Name] = true
					components = append(components, comp)
				}
			}
		}
	}

	return components
}

// parsePythonMetadata parses a Python METADATA file (RFC 822 format).
func parsePythonMetadata(data string) Component {
	var name, version, summary, license string

	scanner := bufio.NewScanner(strings.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()

		// Empty line ends headers
		if line == "" {
			break
		}

		switch {
		case strings.HasPrefix(line, "Name: "):
			name = strings.TrimPrefix(line, "Name: ")
		case strings.HasPrefix(line, "Version: "):
			version = strings.TrimPrefix(line, "Version: ")
		case strings.HasPrefix(line, "Summary: "):
			summary = strings.TrimPrefix(line, "Summary: ")
		case strings.HasPrefix(line, "License: "):
			license = strings.TrimPrefix(line, "License: ")
		}
	}

	comp := Component{
		Type:    "library",
		Name:    name,
		Version: version,
		PURL:    fmt.Sprintf("pkg:pypi/%s@%s", strings.ToLower(name), version),
		Properties: []Property{
			{Name: "mantle:source", Value: "filesystem"},
			{Name: "mantle:ecosystem", Value: "python"},
		},
	}

	if summary != "" {
		comp.Description = summary
	}
	if license != "" {
		comp.Licenses = []LicenseEntry{
			{License: LicenseID{Name: license}},
		}
	}

	return comp
}

type nodeScanner struct{}

func (s *nodeScanner) Name() string { return "nodejs" }

// Scan finds Node.js packages by reading package.json files
// from node_modules directories.
func (s *nodeScanner) Scan(ctx context.Context, ref client.Reference) []Component {
	searchPaths := []string{
		"/app/node_modules",
		"/usr/lib/node_modules",
		"/usr/local/lib/node_modules",
	}

	var components []Component
	seen := make(map[string]bool)

	for _, nmPath := range searchPaths {
		comps, err := scanNodeModules(ctx, ref, nmPath, seen)
		if err != nil {
			continue
		}
		components = append(components, comps...)
	}

	return components
}

func scanNodeModules(ctx context.Context, ref client.Reference, nmPath string, seen map[string]bool) ([]Component, error) {
	entries, err := safeReadDir(ctx, ref, nmPath)
	if err != nil {
		return nil, err
	}

	components := make([]Component, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() || strings.HasPrefix(entry.GetPath(), ".") {
			continue
		}

		pkgPath := entry.GetPath()
		// Handle scoped packages (@org/pkg)
		if strings.HasPrefix(pkgPath, "@") {
			scopedEntries, err := safeReadDir(ctx, ref, filepath.Join(nmPath, pkgPath))
			if err != nil {
				continue
			}
			for _, se := range scopedEntries {
				if !se.IsDir() {
					continue
				}
				fullPath := filepath.Join(nmPath, pkgPath, se.GetPath(), "package.json")
				if comp, ok := readNodePackageJSON(ctx, ref, fullPath); ok && !seen[comp.Name] {
					seen[comp.Name] = true
					components = append(components, comp)
				}
			}
			continue
		}

		fullPath := filepath.Join(nmPath, pkgPath, "package.json")
		if comp, ok := readNodePackageJSON(ctx, ref, fullPath); ok && !seen[comp.Name] {
			seen[comp.Name] = true
			components = append(components, comp)
		}
	}
	return components, nil
}

// readNodePackageJSON reads and parses a single package.json.
func readNodePackageJSON(ctx context.Context, ref client.Reference, path string) (Component, bool) {
	data, err := ref.ReadFile(ctx, client.ReadRequest{Filename: path})
	if err != nil {
		return Component{}, false
	}
	return parseNodePackageJSON(data)
}

// parseNodePackageJSON parses package.json bytes.
func parseNodePackageJSON(data []byte) (Component, bool) {
	var pkg struct {
		Name        string      `json:"name"`
		Version     string      `json:"version"`
		Description string      `json:"description"`
		License     interface{} `json:"license"`
		Licenses    interface{} `json:"licenses"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil || pkg.Name == "" {
		return Component{}, false
	}

	comp := Component{
		Type:    "library",
		Name:    pkg.Name,
		Version: pkg.Version,
		PURL:    fmt.Sprintf("pkg:npm/%s@%s", pkg.Name, pkg.Version),
		Properties: []Property{
			{Name: "mantle:source", Value: "filesystem"},
			{Name: "mantle:ecosystem", Value: "nodejs"},
		},
	}

	if pkg.Description != "" {
		comp.Description = pkg.Description
	}

	var licenseStrs []string

	if pkg.License != nil {
		switch v := pkg.License.(type) {
		case string:
			licenseStrs = append(licenseStrs, v)
		case map[string]interface{}:
			if typ, ok := v["type"].(string); ok {
				licenseStrs = append(licenseStrs, typ)
			}
		}
	}

	if pkg.Licenses != nil {
		if arr, ok := pkg.Licenses.([]interface{}); ok {
			for _, item := range arr {
				if m, ok := item.(map[string]interface{}); ok {
					if typ, ok := m["type"].(string); ok {
						licenseStrs = append(licenseStrs, typ)
					}
				}
			}
		}
	}

	for _, l := range licenseStrs {
		if l != "" {
			comp.Licenses = append(comp.Licenses, LicenseEntry{License: LicenseID{Name: l}})
		}
	}

	return comp, true
}

// safeReadDir reads a directory, returning nil on error (directory doesn't exist).
func safeReadDir(ctx context.Context, ref client.Reference, path string) ([]*fstypes.Stat, error) {
	return ref.ReadDir(ctx, client.ReadDirRequest{Path: path})
}

// maxGoBinarySize is the maximum file size (100 MB) we'll read for Go build info scanning.
const maxGoBinarySize = 100 * 1024 * 1024

// elfMagic is the first 4 bytes of an ELF binary.
var elfMagic = []byte{0x7f, 'E', 'L', 'F'}

type goScanner struct{}

func (s *goScanner) Name() string { return "go" }

// Scan finds Go binaries and extracts embedded module dependency info.
func (s *goScanner) Scan(ctx context.Context, ref client.Reference) []Component {
	searchDirs := []string{
		"/usr/bin",
		"/usr/local/bin",
		"/app",
		"/opt",
	}

	var components []Component
	seen := make(map[string]bool)

	for _, dir := range searchDirs {
		entries, err := safeReadDir(ctx, ref, dir)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			if entry.IsDir() || entry.Size > maxGoBinarySize {
				continue
			}

			filePath := filepath.Join(dir, entry.GetPath())
			if comps := processGoBinary(ctx, ref, filePath, seen); len(comps) > 0 {
				components = append(components, comps...)
			}
		}
	}

	return components
}

func processGoBinary(ctx context.Context, ref client.Reference, filePath string, seen map[string]bool) []Component {
	// Read first 4 bytes to check ELF magic
	data, err := ref.ReadFile(ctx, client.ReadRequest{
		Filename: filePath,
		Range:    &client.FileRange{Offset: 0, Length: 4},
	})
	if err != nil || len(data) < 4 {
		return nil
	}
	if !bytes.Equal(data[:4], elfMagic) {
		return nil
	}

	// Read the full binary
	fullData, err := ref.ReadFile(ctx, client.ReadRequest{Filename: filePath})
	if err != nil {
		return nil
	}

	bi, err := buildinfo.Read(bytes.NewReader(fullData))
	if err != nil {
		return nil // Not a Go binary or no build info
	}

	components := make([]Component, 0, len(bi.Deps))
	for _, dep := range bi.Deps {
		key := dep.Path + "@" + dep.Version
		if seen[key] {
			continue
		}
		seen[key] = true

		components = append(components, Component{
			Type:    "library",
			Name:    dep.Path,
			Version: dep.Version,
			PURL:    fmt.Sprintf("pkg:golang/%s@%s", dep.Path, dep.Version),
			Properties: []Property{
				{Name: "mantle:source", Value: "filesystem"},
				{Name: "mantle:ecosystem", Value: "go"},
			},
		})
	}
	return components
}

type javaScanner struct{}

func (s *javaScanner) Name() string { return "java" }

// Scan finds JAR files and extracts Maven pom.properties from within.
func (s *javaScanner) Scan(ctx context.Context, ref client.Reference) []Component {
	searchDirs := []string{
		"/app/lib",
		"/app",
		"/opt",
		"/usr/share/java",
		"/usr/local/lib",
	}

	var components []Component
	seen := make(map[string]bool)

	for _, dir := range searchDirs {
		entries, err := safeReadDir(ctx, ref, dir)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.GetPath(), ".jar") {
				continue
			}

			jarPath := filepath.Join(dir, entry.GetPath())
			jarData, err := ref.ReadFile(ctx, client.ReadRequest{Filename: jarPath})
			if err != nil {
				continue
			}

			jarComps := parseJAR(jarData)
			for i := range jarComps {
				c := &jarComps[i]
				key := c.Name + "@" + c.Version
				if !seen[key] {
					seen[key] = true
					components = append(components, *c)
				}
			}
		}
	}

	return components
}

// parseJAR reads a JAR (ZIP) and extracts Maven components from pom.properties.
func parseJAR(data []byte) []Component {
	r, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil
	}

	components := make([]Component, 0, len(r.File))

	for _, f := range r.File {
		// Look for META-INF/maven/*/*/pom.properties
		if !strings.HasPrefix(f.Name, "META-INF/maven/") ||
			!strings.HasSuffix(f.Name, "/pom.properties") {
			continue
		}

		rc, err := f.Open()
		if err != nil {
			continue
		}

		comp := parsePomProperties(rc)
		_ = rc.Close()

		if comp.Name != "" {
			components = append(components, comp)
		}
	}

	return components
}

// parsePomProperties parses a Maven pom.properties file.
func parsePomProperties(r interface{ Read([]byte) (int, error) }) Component {
	var groupID, artifactID, version string

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key, val := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
		switch key {
		case "groupId":
			groupID = val
		case "artifactId":
			artifactID = val
		case "version":
			version = val
		}
	}

	if artifactID == "" {
		return Component{}
	}

	name := artifactID
	purl := fmt.Sprintf("pkg:maven/%s/%s@%s", groupID, artifactID, version)
	if groupID != "" {
		name = groupID + ":" + artifactID
	}

	return Component{
		Type:    "library",
		Name:    name,
		Version: version,
		PURL:    purl,
		Properties: []Property{
			{Name: "mantle:source", Value: "filesystem"},
			{Name: "mantle:ecosystem", Value: "java"},
		},
	}
}

type dotnetScanner struct{}

func (s *dotnetScanner) Name() string { return "dotnet" }

// Scan finds .deps.json files and extracts NuGet package references.
func (s *dotnetScanner) Scan(ctx context.Context, ref client.Reference) []Component {
	searchDirs := []string{
		"/app",
		"/opt",
		"/usr/share",
	}

	var components []Component
	seen := make(map[string]bool)

	for _, dir := range searchDirs {
		entries, err := safeReadDir(ctx, ref, dir)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.GetPath(), ".deps.json") {
				continue
			}

			filePath := filepath.Join(dir, entry.GetPath())
			data, err := ref.ReadFile(ctx, client.ReadRequest{Filename: filePath})
			if err != nil {
				continue
			}

			comps := parseDepsJSON(data)
			for i := range comps {
				c := &comps[i]
				key := c.Name + "@" + c.Version
				if !seen[key] {
					seen[key] = true
					components = append(components, *c)
				}
			}
		}
	}

	return components
}

// parseDepsJSON parses a .NET .deps.json file and extracts NuGet packages.
func parseDepsJSON(data []byte) []Component {
	var deps struct {
		Libraries map[string]struct {
			Type string `json:"type"`
		} `json:"libraries"`
	}

	if err := json.Unmarshal(data, &deps); err != nil {
		return nil
	}

	components := make([]Component, 0, len(deps.Libraries))

	for nameVersion, lib := range deps.Libraries {
		// Keys are "PackageName/Version"
		parts := strings.SplitN(nameVersion, "/", 2)
		if len(parts) != 2 {
			continue
		}

		name, version := parts[0], parts[1]

		// Only include NuGet packages, skip project references
		if lib.Type != "package" {
			continue
		}

		components = append(components, Component{
			Type:    "library",
			Name:    name,
			Version: version,
			PURL:    fmt.Sprintf("pkg:nuget/%s@%s", name, version),
			Properties: []Property{
				{Name: "mantle:source", Value: "filesystem"},
				{Name: "mantle:ecosystem", Value: "dotnet"},
			},
		})
	}

	return components
}
