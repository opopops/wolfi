# prometheus-node-exporter

prometheus-node-exporter is a Prometheus project used to collect Prometheus metrics in Kubernetes.

## Versions

| 📌 Version    | ⬇️ Pull URL                                                  |
| ------------ | ----------------------------------------------------------- |
| latest       | ghcr.io/opopops/wolfi/prometheus-node-exporter:latest       |
| latest-shell | ghcr.io/opopops/wolfi/prometheus-node-exporter:latest-shell |
| 1.8          | ghcr.io/opopops/wolfi/prometheus-node-exporter:1.8          |
| 1.8-shell    | ghcr.io/opopops/wolfi/prometheus-node-exporter:1.8-shell    |

## ✅ Verify the Provenance

GitHub CLI ([gh](https://cli.github.com/)) can be used to retrieve the build provenance, which details the exact commit, workflow, and runner that produced the image:

- **Production image**

```shell
gh attestation verify \
  --owner opopops \
  oci://ghcr.io/opopops/wolfi/prometheus-node-exporter:latest
```

- **Shell image**

```shell
gh attestation verify \
  --owner opopops \
  oci://ghcr.io/opopops/wolfi/prometheus-node-exporter:latest-shell
```

## 📦 **Image Verification**

All official images are **cryptographically signed** using [Sigstore Cosign](https://www.sigstore.dev/).

### ✅ Verify the Image Signature

To ensure the image is authentic and has not been tampered with, use the following command:

- **Production image**

```shell
cosign verify \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
  --certificate-identity=https://github.com/opopops/wolfi/.github/workflows/release.yaml@refs/heads/main \
  ghcr.io/opopops/wolfi/prometheus-node-exporter:latest | jq
```

- **Shell image**

```shell
cosign verify \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
  --certificate-identity=https://github.com/opopops/wolfi/.github/workflows/release.yaml@refs/heads/main \
  ghcr.io/opopops/wolfi/prometheus-node-exporter:latest-shell | jq
```

### 📦 **Image SBOMs**

To enhance transparency, we generate SBOMs for each release. SBOMs are available directly from the container registry
and can be verified using using [Sigstore Cosign](https://www.sigstore.dev/).

#### ✅ Verify the Image Attestations

- **Production image**

```shell
cosign verify-attestation \
  --type=https://spdx.dev/Document \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
  --certificate-identity=https://github.com/opopops/wolfi/.github/workflows/release.yaml@refs/heads/main \
  ghcr.io/opopops/wolfi/prometheus-node-exporter:latest
```

- **Shell image**

```shell
cosign verify-attestation \
  --type=https://spdx.dev/Document \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
  --certificate-identity=https://github.com/opopops/wolfi/.github/workflows/release.yaml@refs/heads/main \
  ghcr.io/opopops/wolfi/prometheus-node-exporter:latest-shell
```

This will pull in the signature for the attestation specified by the --type parameter, which in this case is the SPDX attestation. You will receive output that verifies the SBOM attestation signature in cosign's transparency log:

```shell
Verification for ghcr.io/opopops/wolfi/prometheus-node-exporter:latest --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - Existence of the claims in the transparency log was verified offline
  - The code-signing certificate was verified using trusted certificate authority certificates
Certificate subject: https://github.com/opopops/wolfi/.github/workflows/release.yaml@refs/heads/main
Certificate issuer URL: https://token.actions.githubusercontent.com
GitHub Workflow Trigger: push
GitHub Workflow SHA: ced6b3cfab1341509de55bff7c0389ce81f73aae
GitHub Workflow Name: python
GitHub Workflow Repository: GitGuardian/wolfi
GitHub Workflow Ref: refs/heads/main
...
```

#### ✅ Download the Image SBOM Attestations

To download an attestation, use the `cosign` download attestation command and provide both the predicate type and the build platform. For example, the following command will obtain the SBOM for the python image on `linux/amd64`:

- **Production image**

```shell
cosign download attestation \
  --platform=linux/amd64 \
  --predicate-type=https://spdx.dev/Document \
  ghcr.io/opopops/wolfi/prometheus-node-exporter:latest | jq -r .payload | base64 -d | jq .predicate
```

- **Shell image**

```shell
cosign download attestation \
  --platform=linux/amd64 \
  --predicate-type=https://spdx.dev/Document \
  ghcr.io/opopops/wolfi/prometheus-node-exporter:latest-shell | jq -r .payload | base64 -d | jq .predicate
```
