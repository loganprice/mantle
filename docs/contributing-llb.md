# Understanding BuildKit LLB (Low-Level Builder)

If you are contributing to Mantle, you will likely encounter BuildKit's Low-Level Builder (LLB). It is the intermediate representation that BuildKit uses to assemble containers. This document explains what LLB is and how Mantle uses it.

## What is LLB?

Unlike a `Dockerfile` which is parsed procedurally line-by-line (`RUN apt-get...`, `COPY ...`), LLB is a **Directed Acyclic Graph (DAG)** of build instructions.

Think of LLB as assembly language for container builds. A `Dockerfile` is just one of many possible frontends that compile down into LLB. Mantle is another frontend that compiles `mantle.yaml` into LLB.

When you use the `github.com/moby/buildkit/client/llb` package in Go, you are not *executing* commands. You are *declaring* a graph of operations for the BuildKit daemon to solve later.

## Core Concepts in Mantle

### 1. `llb.State`
An `llb.State` represents an immutable filesystem at a specific point in the graph.
*   `llb.Scratch()` creates an empty, 0-byte filesystem.
*   `llb.Image("alpine")` creates a state containing the Alpine Linux filesystem.
*   `state.Run(...)` returns a completely *new* state representing the filesystem after the command has executed.

### 2. Operations are Lazy
When you call `llb.Merge()`, `llb.Copy()`, or `llb.Diff()`, absolutely nothing happens on your computer. You are just adding nodes and edges to the DAG in memory. 

Execution only happens once the entire graph is serialized and sent to the BuildKit solver in `cmd/mantle/main.go` via `c.Solve(...)`.

## How Mantle Uses LLB

Mantle builds its graph in `internal/assembler/assembler.go`: 

1.  **Packages**: Mantle resolves `wolfi` APKs and creates a base `llb.State`.
2.  **Assets**: It fetches remote assets and creates parallel branches in the DAG.
3.  **Pipelines**: In `internal/pipeline/pipeline.go`, it spins up complex sub-graphs. 
    * It runs an ephemeral container (`base.Run(...)`).
    * It runs a diff between before and after (`llb.Diff(base, after)`).
    * It extracts the diff to a clean `llb.Scratch()`.
4.  **Merge**: It merges all these discrete states back into one final `rootfs` using `llb.Merge()`.

## Tips for Contributors

### Don't Panic About "Context"
Many LLB functions require `llb.Local("context")`. This just maps back to the local directory where `docker build` was executed. 

### Debugging Your Graph
Because LLB is declarative, standard `fmt.Println` debugging won't show you what is happening inside the container. 
If your graph is failing during `c.Solve()`, the error will usually come from the BuildKit daemon. 

When constructing the graph, always use `llb.WithCustomName("[mantle] doing something")`. This makes the Docker build output human-readable, so when an error occurs, the user (and you) can see exactly which node in the graph failed.

```go
// Good: Creates a clear node name in the BuildKit output
rootfs = llb.Merge(layers, llb.WithCustomName("[mantle] merge final rootfs"))
```

### Determinism is Key
LLB is heavily cached based on the exact structure of the graph. If you iterate over a map in Go, map iteration is randomized. This will create a differently structured graph every time, busting the BuildKit cache! 
*Always sort maps before translating them into LLB operations.* (See `sortedKeys` in `internal/pipeline/pipeline.go`).
