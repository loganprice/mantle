# The `mantle.yaml` Specification

Mantle replaces Dockerfiles with a declarative `mantle.yaml` file. This document details the schema and configuration options available.

## Structure Overview

A complete `mantle.yaml` generally consists of the following top-level blocks:

```yaml
# syntax=ghcr.io/loganprice/mantle:main
version: "1.0"
args: {}
contents: {}
assets: []
pipeline: []
runtime: {}
```

---

### `syntax` Directive
The first line of your file **must** be the BuildKit syntax directive. This tells the Docker builder to use our frontend instead of the standard Dockerfile parser.
```yaml
# syntax=ghcr.io/loganprice/mantle:main
```

---

### `version` (string, required)
The schema version of the `mantle.yaml` file. Currently, the only supported version is `"1.0"`.

---

### `args` (map[string]string, optional)
Build arguments that can be injected via `docker build --build-arg KEY=VALUE`. 
Mantle supports Go's `text/template` syntax to inject these arguments directly into the YAML before it is parsed.

In addition to user-defined arguments under `.BuildArgs`, Mantle also injects two default variables you can template:
- `{{ .Arch }}` (e.g., `amd64`, `arm64`)
- `{{ .Platform }}` (e.g., `linux/amd64`)

**Example:**
```yaml
args:
  PYTHON_VERSION: "3.14"
contents:
  packages:
    - python-{{ .BuildArgs.PYTHON_VERSION }}
```


---

### `contents` (object, required)
Defines the base operating system packages that will be installed into the image. Mantle relies exclusively on `apk`-based package resolution (designed explicitly for Wolfi).

- **`repositories`** (array of strings, required): URLs to the APK repositories (e.g., `https://packages.wolfi.dev/os`).
- **`keyring`** (array of strings, required): URLs to the RSA public keys used to verify the repository signatures.
- **`packages`** (array of strings, required): List of packages to install into the final image.
- **`squash`** (boolean, optional): If `true`, all package layers are merged into a single filesystem layer. Default is `false`.

---

### `assets` (array of objects, optional)
Permits injecting files and directories from the local build context or external locations directly into the resulting image.

- **`name`** (string, required): A unique identifier for the asset layer.
- **`source`** (string, required): The URI of the asset. Supports three schemas:
  - `local://<dir>`: Path relative to your local build context. 
  - `https://<url>`: An external HTTP download.
  - `oci://<image>`: Extract files from another container image.
- **`destination`** (string, required): The absolute path in the final image where the asset should be placed.
- **`from_path`** (string, optional): When using `oci://`, specifies the path *inside* the source container to extract.
- **`sha256`** (string, required for HTTPS): The expected SHA256 checksum of the remote file to enforce integrity. Optional for local/oci sources.
- **`uid`** / **`gid`** (int, optional): Ownership assignment for the injected files.

**Example:**
```yaml
assets:
  - name: ca-certs
    source: https://curl.se/ca/cacert.pem
    destination: /etc/ssl/certs/ca-certificates.crt
    sha256: "b0b...1234"
```

---

### `pipeline` (array of objects, optional)
Pipelines are ephemeral build stages used to compile source code, install language dependencies (like `npm` or `pip`), or generate static files. Build tools (`gcc`, `curl`, `pip`) used inside the pipeline step **do not** end up in the final image, ensuring a minimal attack surface.

Each list item is a `Step`:
- **`name`** (string, required): The name of the pipeline step.
- **`uses`** (string, required): The base container image to execute the step inside (e.g., `golang:1.22`).
- **`workdir`** (string, optional): The directory where the commands will execute. The base system rootfs is natively mounted here.
- **`run`** (array of strings, required): Sequential terminal commands to execute in an `/bin/sh` shell.
- **`env`** (map[string]string, optional): Environment variables passed into the `run` step.
- **`mounts`** (array of objects, optional): Runtime mounts injected into the ephemeral step container to accelerate builds or supply credentials securely. Available types:
  - `type: cache`: Mounts persistent cache directories (e.g., Go build caches, pip caches).
    - `target` (string): The path to mount inside the step. This directory is persisted across separate builds.
  - `type: secret`: Securely inject certificates, API tokens, or SSH keys without committing them to the container's history or final layers. Injected via `docker build --secret id=NAME,src=FILE`.
    - `target` (string): The absolute path inside the step to place the secret (e.g., `/root/.netrc`).
    - `source` (string, optional): The BuildKit secret ID. Defaults to the base name of the `target`.
- **`exports`** (array of objects, required): The files/directories that should be extracted from this step and injected into the final image.
  - `source` (string): Path generated in the pipeline.
  - `destination` (string): Path to place it in the final image.

---

### `runtime` (object, required)
Configures the OCI runtime settings of the final container image.

- **`user`** (int, required): The numeric UID the container processes will run as. Setting this to `0` (root) will actively fail the build unless `force_root` is enabled.
- **`workdir`** (string, required): The working directory upon container start.
- **`entrypoint`** (array of strings, required): The command that execution starts with.
- **`args`** (array of strings, optional): Default arguments appended to the entrypoint.
- **`env`** (map[string]string, optional): Environment variables injected into the final image.
- **`force_root`** (boolean, optional): Set to `true` to actively bypass the security guardrail that prevents running containers as root UID `0`.
