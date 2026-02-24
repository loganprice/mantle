# Mantle Architecture Guide

This document covers the high-level internal architecture of the Mantle BuildKit frontend.

Instead of interpreting procedural scripts (like `Dockerfile`), the frontend reads a declarative YAML standard. It programmatically translates a `mantle.yaml` file into a Low Level Builder (LLB) directed acyclic graph (DAG), which BuildKit natively understands.

## Overview Flow

The entrypoint resides in `cmd/mantle/main.go`. When BuildKit invokes the `Build` function, it follows a 7-step pipeline sequence orchestrated largely by `internal/assembler`:

1.  **Parse and Validate the Blueprint**
2.  **Determine Target Architecture**
3.  **Build Graph Assembly (`Assembler.Assemble`)**
4.  **Solve the Global Definition**
5.  **Auto-discover `PATH`**
6.  **Generate and Attach SBOM**
7.  **Attach OCI Image Configuration Metadata**

### 1. Build Graph Assembly (`internal/assembler/assembler.go`)

The Assembler converts the validated `config.Spec` into a massive `llb.State` chain. Instead of executing containers procedurally, the frontend maps data sources to root filesystems.

#### A. Keyring + Wolfi Package Resolution (`internal/resolver`)
Mantle is purpose-built to pull `.apk` formats from the [Wolfi Linux](https://github.com/wolfi-dev/os) ecosystem.
Instead of running `apk add`, the resolver:
- Requests the `APKINDEX.tar.gz` from the target repository.
- Extracts signatures and verifies them against the provided `contents.keyring` RSAs (via `internal/signature`).
- Computes dependencies and discovers `.apk` download URLs.
- Executes `llb.HTTP` nodes to fetch the raw packages natively into LLB cache.
- Extracts each `.apk` tarball directly into a layer structure, intentionally skipping runtime "install triggers" entirely.

#### B. Asset Injection (`internal/assets`)
Handles moving untrusted files into the image natively without building them.
- **`local://`**: Direct map to `llb.Local`. Copies files from the host workspace payload.
- **`https://`**: Maps directly to `llb.HTTP` nodes with strict `sha256` integrity.
- **`oci://`**: Mounts an upstream registry image via `llb.Image` and extracts specific filesystem paths using `llb.Copy`.

#### C. Ephemeral Pipeline Stages (`internal/pipeline`)
Mantle's "Pipelines" behave exactly like multi-stage Docker builds safely abstracted.
1. It natively mounts the base rootfs over into the transient pipeline container image.
2. It executes the array of `run:` shell commands (like `go build main.go` or `npm install`). Mounts caches to natively speed up this process over identical runs.
3. The real magic: It utilizes `llb.Diff` between the state *before* `run:` and the state *after*. The result contains only the artifacts explicitly generated.
4. Finally, it copies strictly what the user declared in `exports` into the new layer.

The heavily polluted build container and toolchains (`go`, `npm`, `gcc`) are discarded and never interact with the base image graph.

#### D. Layer Merging & Hardening (`internal/security`)
After completing the extraction and export phases, the Assembler takes all resulting DAG layers (OS Packages, API assets, built artifacts) and flattens them concurrently using `llb.Merge()`. 

Critically, a final security pass creates `llb.Rm()` nodes targeting every known shell path (e.g., `/bin/sh`, `/bin/bash`), entirely sanitizing the merged system.

### 2. Solving and Finalization

Once the `Assembler` returns the completed DAG `Definition`, `main.go` halts internal logic and delegates control back to BuildKit:

```go
solveRes, err := client.Solve(ctx, client.SolveRequest{
    Definition: asmRes.Definition.ToPB(),
})
```

BuildKit optimally processes the LLB node tree across parallel workers and heavily cached graphs. 

When returned, the frontend executes its metadata passes:
1. **Dynamic `$PATH` Discovery:** Crawls `/usr/bin`, `/opt/bin`, and `/sbin`, generating an optimal string map rather than relying on standard hardcoded Linux defaults.
2. **SBOM:** Invokes the `internal/sbom.GenerateSBOM()` generator against metadata fetched from the runtime spec to seamlessly bundle a CycloneDX v1.5 JSON trace, attaching it safely to the returned BuildKit references.

---

## Technical Considerations

### Avoiding Parser Bottlenecks
During development, `jsonschema.Compiler.Compile()` and double-`yaml.Unmarshal()` routines were identified as high memory allocations. Internally, Mantle pre-compiles and strictly caches (`sync.Once`) its `schema.json` globally to optimize memory usage during repeated BuildKit parses. 

### Enforcing Strict Limits
Due to potential CPU exhaustion or memory-over-allocation vulnerabilities inherently possible when loading remote assets, decompressing malicious gzip streams, or parsing unverified `.SIGN.RSA` streams from untrusted `.apk` blobs, the BuildKit nodes strictly bind to internal `io.LimitReader` wrappers capping processing buffers to prevent Denial of Service (DoS) conditions inside the frontend daemon.
