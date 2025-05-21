import dagger
from dagger import dag, field, function, object_type


@object_type
class Builder:
    """Wolfi Builder"""

    image: str | None = field(default="cgr.dev/chainguard/wolfi-base:latest")
    user: str | None = field(default="nonroot")
    apko_version: str | None = field(default="latest")
    crane_version: str | None = field(default="latest")
    cosign_version: str | None = field(default="latest")
    grype_version: str | None = field(default="latest")

    @function
    def container(self) -> dagger.Container:
        """Returns the builder container"""
        apko_pkg = "apko"
        if self.apko_version != "latest":
            apko_pkg = f"{apko_pkg}~{self.apko_version}"

        cosign_pkg = "cosign"
        if self.cosign_version != "latest":
            cosign_pkg = f"{cosign_pkg}~{self.cosign_version}"

        crane_pkg = "crane"
        if self.crane_version != "latest":
            crane_pkg = f"{crane_pkg}~{self.crane_version}"

        grype_pkg = "grype"
        if self.grype_version != "latest":
            grype_pkg = f"{grype_pkg}~{self.grype_version}"

        return (
            dag.container()
            .from_(address=self.image)
            .with_env_variable("BUILD_DIR", "/build")
            .with_env_variable("CACHE_DIR", "/cache")
            .with_env_variable("SOURCE_DIR", "/source")
            .with_env_variable("APKO_CACHE_DIR", "${CACHE_DIR}/apko", expand=True)
            .with_env_variable(
                "APKO_CONFIG_FILE", "${BUILD_DIR}/apko.yaml", expand=True
            )
            .with_env_variable(
                "APKO_IMAGE_TARBALL", "${BUILD_DIR}/image.tar", expand=True
            )
            .with_env_variable("APKO_SBOM_DIR", "${BUILD_DIR}", expand=True)
            .with_env_variable("COSIGN_YES", "true")
            .with_env_variable("GRYPE_CACHE_DIR", "${CACHE_DIR}/grype", expand=True)
            .with_env_variable(
                "GRYPE_DB_CACHE_DIR", "${GRYPE_CACHE_DIR}/db", expand=True
            )
            .with_env_variable(
                "GRYPE_REPORT_FILE", "${BUILD_DIR}/grype.report", expand=True
            )
            .with_env_variable("DOCKER_CONFIG", "/tmp/docker")
            .with_env_variable("DOCKER_HOST", "unix:///tmp/docker.sock")
            .with_user("root")
            .with_exec(
                [
                    "apk",
                    "add",
                    "--no-cache",
                    "docker-cli",
                    apko_pkg,
                    crane_pkg,
                    cosign_pkg,
                    grype_pkg,
                ]
            )
            .with_exec(
                ["mkdir", "-m", "777", "-p", "$BUILD_DIR", "$CACHE_DIR", "$SOURCE_DIR"],
                expand=True,
            )
            .with_mounted_cache(
                "$APKO_CACHE_DIR",
                dag.cache_volume("apko-cache"),
                sharing=dagger.CacheSharingMode("SHARED"),
                owner=self.user,
                expand=True,
            )
            .with_mounted_cache(
                "$GRYPE_CACHE_DIR",
                dag.cache_volume("grype-cache"),
                sharing=dagger.CacheSharingMode("SHARED"),
                owner=self.user,
                expand=True,
            )
            .with_user(self.user)
        )
