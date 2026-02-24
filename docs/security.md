# Mantle Security & Zero-CVE

Mantle is inherently designed as a "secure-by-default" builder. Where traditional Dockerfiles prioritize extreme flexibility, Mantle prioritizes guardrails and supply chain security.

This document details the exact mechanisms Mantle uses to secure your containers.

---

## 1. Zero-Known Vulnerabilities (Powered by Wolfi)
Most security scanners throw hundreds of CVE alerts for standard `ubuntu` or `debian` base images within weeks of their release.

Mantle completely shifts this paradigm by utilizing the **[Wolfi Linux](https://github.com/wolfi-dev)** ecosystem as its foundational layer.
- **Undistro Model:** Wolfi is an "undistro"—it has no package manager (`apk` is used during build, but not included in runtime) and no pre-installed utilities like `systemd` or `cron`.
- **Rolling Releases:** Wolfi packages are rebuilt continually. When a CVE is disclosed in an upstream component (like OpenSSL), a patch is applied and the Wolfi package is rolled instantly.
- **Granular Packaging:** Wolfi breaks monolithic packages down. You only install exactly what your app needs, leaving no idle code in the image to become a CVE liability later.

Because of this, Mantle images frequently scan with **0 known vulnerabilities** on day one.

---

## 2. Shell-less by Default
In traditional Dockerfiles, every `RUN` command injects a layer that modifies the filesystem. To execute those commands, the image *must* contain a shell (`/bin/sh` or `/bin/bash`).

Mantle separates the *build phase* from the *runtime phase* entirely using **ephemeral pipelines**. 
The final image constructed by Mantle **aggressively purges all known shells**:
```go
// internal/security/guardrails.go
var shellPaths = []string{
	"/bin/sh", "/bin/ash", "/bin/bash",
	"/bin/dash", "/bin/zsh", "/usr/bin/sh",
}
```

**Why is this important?**
If your application suffers a Remote Code Execution (RCE) vulnerability, the attacker cannot easily gain a reverse shell because the container itself literally does not possess a shell binary or core utilities (`curl`, `wget`) to download exploit payloads.

---

## 3. Disallowing Root Escalation
By default, Docker containers run as the `root` user (UID 0). Running web servers and process workloads as `root` inside the container makes malicious container-escapes exponentially easier for an attacker.

Mantle enforces a strict **non-root runtime guardrail**. If your `mantle.yaml` fails to set a numeric unprivileged user (e.g., `user: 1000`), or explicitly attempts to set `user: 0`, the build will **fail**:

```text
[mantle] Error: security violation: runtime.user=0 (root) is not allowed; set force_root: true to override this guardrail
```

To run as root, you must actively declare `force_root: true` in your spec, signaling that you understand the risks.

---

## 4. Hardware and Supply Chain Integrity
Mantle protects the integrity of the build process itself using several hardened features.

### A. Automatic CycloneDX 1.5 SBOM
Mantle automatically generates a Software Bill of Materials (SBOM) natively during the BuildKit extraction phase.
- It scans all `apk` components natively from the resolved `contents` block.
- It includes all ingested generic `assets`.
- It appends the SBOM natively to the OCI properties via `containerimage.sbom`, ensuring compatibility with the OCI Distribution v1.1.0 `Referrers API`.

### B. Reproducible Builds (`SOURCE_DATE_EPOCH`)
Mantle guarantees **Bit-for-Bit Reproducible Builds**. 
If you provide Mantle with identical inputs, it will produce an image with the exact same `sha256` digest hash.

To achieve this, Mantle respects the `SOURCE_DATE_EPOCH` standard. Since generic image creation sets timestamps to `time.Now()`, building an image twice produces two different hashes. By exporting `SOURCE_DATE_EPOCH` (like the last Git commit timestamp), both the image config `org.opencontainers.image.created` and the internal SBOM timestamps are pinned statically.

### C. Remote Checksum Pinning
When injecting dependencies via `https://` assets, Mantle outright rejects the configuration if a 64-character SHA256 checksum is not strictly provided. This eliminates the risk of an untrusted or man-in-the-middle (MITM) server returning a malicious binary payload without halting the builder.
