# Mantle

Mantle is a declarative, security-first BuildKit frontend designed to build extremely minimal, reproducible, and zero-CVE OCI container images. 

By replacing the traditional, procedural `Dockerfile` with a strict, intent-based `mantle.yaml` specification, Mantle eliminates whole classes of container vulnerabilities by default.

## Why Mantle?

Traditional Dockerfiles are procedural (`RUN apt-get update && apt-get install...`), which often leads to bloated images, left-over build tools, non-reproducible outputs, and deeply embedded vulnerabilities.

Mantle completely changes the build paradigm:
- **Declarative Spec:** You define *what* you want in the image (packages, assets, runtime config), not *how* to build it.
- **Wolfi-Powered:** Mantle natively resolves packages from the [Wolfi](https://github.com/wolfi-dev) ecosystem—a Linux undistro designed specifically for container environments, providing rolling updates and zero known CVEs.
- **Shell-less by Default:** Mantle removes all shells (`/bin/sh`, `/bin/bash`) from the final image, drastically reducing the attack surface.
- **Bit-for-Bit Reproducible:** Fully supports `SOURCE_DATE_EPOCH`. Identical inputs guarantee identical image digests.
- **Automatic SBOMs:** Every build automatically generates a highly accurate CycloneDX 1.5 Software Bill of Materials (SBOM) and attaches it natively to the OCI metadata layer.
- **Non-Root Enforced:** The build will fail if you attempt to run the container as user `0` (root) without an explicit override.

---

## Quick Start

### 1. Enable BuildKit
Ensure your Docker daemon has BuildKit enabled.
```bash
export DOCKER_BUILDKIT=1
```

### 2. Create a `mantle.yaml`
Create a file named `mantle.yaml` in your project directory. The very first line must be the syntax directive telling BuildKit to use the Mantle frontend.

```yaml
# syntax=registry.labs.io/mantle:v1
version: "1.0"

# 1. Packages to install (powered by Wolfi)
contents:
  repositories:
    - https://packages.wolfi.dev/os
  keyring:
    - https://packages.wolfi.dev/os/wolfi-signing.rsa.pub
  packages:
    - python-3.12
    - py3-pip

# 2. Inject local code or remote remote assets
assets:
  - name: my-app
    source: local://./src
    destination: /app

# 3. Ephemeral build stages (tools are discarded after export!)
pipeline:
  - name: pip-install
    uses: python:3.12-alpine
    workdir: /app
    run:
      - pip install --no-cache-dir -r requirements.txt
    exports:
      - source: /app
        destination: /app

# 4. Final Image Configuration
runtime:
  user: 1000
  workdir: /app
  entrypoint: ["python", "app.py"]
```

### 3. Build the Image
Build the image exactly as you would with a Dockerfile, but point Docker to the directory containing your `mantle.yaml`.

```bash
docker build -f mantle.yaml -t my-secure-app:latest .
```

---

## Documentation

For deep dives into Mantle's features and specifications, please refer to the detailed documentation located in the `docs/` directory:

- [The `mantle.yaml` Specification](docs/mantle-yaml.md) - A comprehensive guide to the configuration schema.
- [Security & Zero-CVE](docs/security.md) - How Mantle enforces reproducible, secure, and shell-less images.
- [Architecture](docs/architecture.md) - Internal design and how Mantle interacts with the BuildKit LLB.

## License
Apache 2.0
