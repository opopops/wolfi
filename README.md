# Wolfi Base images by opopops

[![License](https://img.shields.io/github/license/opopops/wolfi)](LICENSE)

## Overview

**opopops/Wolfi** is a repository providing a set of **lightweight and secure** container images based on the [Wolfi](https://wolfi.dev/) Linux distribution. These images are designed for security-focused applications, offering a minimal attack surface while ensuring compatibility with modern containerized workloads.

## Features

- **Minimalist & Secure**: Built from scratch using [apko](https://github.com/chainguard-dev/apko) with a focus on security and small footprint.
- **Continuous Updates**: Regularly updated with the latest security patches.
- **Compatibility**: Optimized for OCI-compliant runtime environments.
- **Reproducible Builds**: Ensuring consistency across deployments.
- **Provenance & Security**: All images are signed and come with attestations for enhanced security and trust.

## Available Images

| Image Name                                                     | Pull                                                         |
| -------------------------------------------------------------- | ------------------------------------------------------------ |
| [bash](./images/bash/)                                         | `docker pull ghcr.io/opopops/wolfi/bash`                     |
| [fluent-bit](./images/fluent-bit/)                             | `docker pull ghcr.io/opopops/wolfi/fluent-bit`               |
| [helm](./images/helm/)                                         | `docker pull ghcr.io/opopops/wolfi/helm`                     |
| [infra-tools](./images/infra-tools/)                           | `docker pull ghcr.io/opopops/wolfi/infra-tools`              |
| [ingress-nginx-controller](./images/ingress-nginx-controller/) | `docker pull ghcr.io/opopops/wolfi/ingress-nginx-controller` |
| [loki](./images/loki/)                                         | `docker pull ghcr.io/opopops/wolfi/loki`                     |
| [minio](./images/loki/)                                        | `docker pull ghcr.io/opopops/wolfi/minio`                    |
| [minio-bitnami](./images/minio-bitnami/)                       | `docker pull ghcr.io/opopops/wolfi/minio-bitnami`            |
| [minio-bitnami-client](./images/minio-bitnami-client/)         | `docker pull ghcr.io/opopops/wolfi/minio-bitnami-client`     |
| [nginx](./images/nginx/)                                       | `docker pull ghcr.io/opopops/wolfi/nginx`                    |
| [prometheus](./images/prometheus/)                             | `docker pull ghcr.io/opopops/wolfi/prometheus`               |
| [prometheus-adapter](./images/prometheus-adapter/)             | `docker pull ghcr.io/opopops/wolfi/prometheus-adapter`       |
| [python](./images/python/)                                     | `docker pull ghcr.io/opopops/wolfi/python`                   |
| [shell](./images/shell/)                                       | `docker pull ghcr.io/opopops/wolfi/shell`                    |
| [socat](./images/socat/)                                       | `docker pull ghcr.io/opopops/wolfi/socat`                    |
| [traefik](./images/traefik/)                                   | `docker pull ghcr.io/opopops/wolfi/traefik`                  |