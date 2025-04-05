# Security Policy

This document outlines the security policies, including how to report vulnerabilities, verify artifact integrity, and understand the security measures in place.

---

## 🔑 Provenance and Supply Chain Security

To ensure the integrity of our software, we provide a verifiable provenance for our **Docker images**.
You can find all provenance attestations [here](https://github.com/opopops/wolfi/attestations).

### 🏗️ **Build Provenance**

Our **wolfi-based** container images are built using **GitHub Actions** and follow best practices for **supply chain security** with a declarative approach leveraging **[apko](https://github.com/chainguard-dev/apko)**.

- **Base Image**: [`wolfi-base`](https://github.com/wolfi-dev/os)
- **Build System**: GitHub Actions (workflow: [`release.yml`](./.github/workflows/release.yml))
- **Declarative Build Spec**: [`apko.yaml`](./apko/prod.yaml) defines the image composition
