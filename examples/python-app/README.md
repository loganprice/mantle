# Python App Example

This directory contains a simple Python web server application that demonstrates how to use the Mantle (mantle) frontend.

## structure

- `src/`: Source code (`main.py`) and dependencies (`requirements.txt`).
- `mantle.yaml`: The declarative build configuration.

## Prerequisites

- **Docker**: To build the frontend image.
- **BuildKit**: `buildctl` CLI and a running buildkitd daemon (or `docker buildx` with some configuration).

## How to Build

1. **Build the Frontend Image** (from the root of the repo):
   ```bash
   make docker-build
   ```
   This creates the `mantle:dev` image.

2. **Build the Example App**:
   Navigate to this directory:
   ```bash
   cd examples/python-app
   ```

   Run `buildctl` to build the image using the custom frontend:
   ```bash
   buildctl build \
       --frontend=gateway.v0 \
       --opt source=mantle:dev \
       --local context=. \
       --output type=image,name=python-app:latest
   ```

   This will:
   - Load the `mantle.yaml` from the local context.
   - Use `mantle:dev` to parse it and generate the LLB graph.
   - Execute the build (fetching Wolfi packages, installing pip deps in a secure pipeline, and hardening the final image).
   - Output the result as `python-app:latest` (loaded into your Docker daemon if using the docker exporter, or OCI tarball depending on config).

   *Note: To load directly to Docker, you might need `--output type=docker,name=python-app:latest`.*

3. **Run the App**:
   ```bash
   docker run --rm -p 8080:8080 python-app:latest
   ```
   Visit `http://localhost:8080` to see the "Hello from Mantle!" message.
