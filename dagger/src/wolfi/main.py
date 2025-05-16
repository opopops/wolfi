from typing import Annotated, Self
import yaml
import dagger
from dagger import DefaultPath, Doc, Name, dag, function, object_type

APKO_VERSION = "latest"
CRANE_VERSION = "latest"
COSIGN_VERSION = "latest"
GRYPE_VERSION = "latest"


@object_type
class Wolfi:
    """Wolfi module"""

    source: dagger.Directory
    image: str
    container_: dagger.Container
    builder_: dagger.Container | None
    sbom: dagger.Directory | None

    github_actions: bool | None
    github_actor: str | None
    github_token: dagger.Secret | None
    github_oidc_provider_url: dagger.Secret | None
    github_oidc_provider_token: dagger.Secret | None

    @classmethod
    async def create(
        cls,
        source: Annotated[dagger.Directory, DefaultPath("/"), Doc("Source directory")],
        image: Annotated[str, Doc("wolfi-base image")] = (
            "cgr.dev/chainguard/wolfi-base:latest"
        ),
        github_actions: Annotated[bool, Doc("Enable GitHub Actions")] = False,
        github_actor: Annotated[str, Doc("GitHub Actor")] = "",
        github_token: Annotated[dagger.Secret | None, Doc("GitHub Token")] = None,
        github_oidc_provider_token: Annotated[
            dagger.Secret | None, Doc("GitHub OIDC provider Token")
        ] = None,
        github_oidc_provider_url: Annotated[
            dagger.Secret | None, Doc("GitHub OIDC provider URL")
        ] = None,
    ):
        """Constructor"""
        return cls(
            source=source,
            image=image,
            github_actions=github_actions,
            github_actor=github_actor,
            github_token=github_token,
            github_oidc_provider_token=github_oidc_provider_token,
            github_oidc_provider_url=github_oidc_provider_url,
            container_=dag.container(),
            builder_=None,
            sbom=None,
        )

    def scan_tarball(
        self,
        tarball: Annotated[dagger.File, Doc("File to scan")],
        fail_on: Annotated[
            str,
            Doc(
                "Fails if a vulnerability is found with a severity >= the given severity"
            ),
        ] = "",
        format_: Annotated[str, Doc("Output format"), Name("format")] = "table",
    ) -> dagger.File:
        """Scan a file for vulnerabilities"""
        builder: dagger.Container = self.builder().with_mounted_file(
            "${APKO_IMAGE_TARBALL}", source=tarball, owner="nonroot", expand=True
        )

        cmd: list[str] = [
            "grype",
            "${APKO_IMAGE_TARBALL}",
            "--output",
            format_,
            "--file",
            "$GRYPE_REPORT_FILE",
        ]
        if fail_on:
            cmd.extend(["--fail-on", fail_on])

        return builder.with_exec(
            cmd,
            expand=True,
        ).file("$GRYPE_REPORT_FILE", expand=True)

    @function
    def get_config(self, config: dagger.File) -> dagger.File:
        """Show the configuration derived from loading a YAML file"""
        return (
            self.builder()
            .with_mounted_file(
                "$APKO_CONFIG_FILE", source=config, owner="nonroot", expand=True
            )
            .with_exec(
                ["apko", "show-config", "$APKO_CONFIG_FILE", "--log-level", "ERROR"],
                redirect_stdout="/tmp/config.yaml",
                expand=True,
            )
            .file("/tmp/config.yaml")
        )

    @function
    async def get_image_title(self, config: dagger.File) -> str:
        """Returns the image title from config"""
        config_dict: dict = yaml.safe_load(await self.get_config(config).contents())
        return config_dict["annotations"]["org.opencontainers.image.title"]

    @function
    async def get_platforms(self, config: dagger.File) -> list[dagger.Platform]:
        """Get the platforms from the apko config file"""
        platforms: list[dagger.Platform] = []
        config_dict: dict = yaml.safe_load(await self.get_config(config).contents())
        archs: list[str] = config_dict.get("archs", [])
        for arch in archs:
            if arch in ["amd64", "x86_64"]:
                platforms.append(dagger.Platform("linux/amd64"))
            elif arch in ["arm64", "aarch64"]:
                platforms.append(dagger.Platform("linux/arm64"))
            else:
                continue
        return platforms

    @function
    def builder(self) -> dagger.Container:
        """Returns the builder container"""
        if self.builder_:
            return self.builder_

        apko_pkg = "apko"
        if APKO_VERSION != "latest":
            apko_pkg = f"{apko_pkg}~{APKO_VERSION}"

        cosign_pkg = "cosign"
        if COSIGN_VERSION != "latest":
            cosign_pkg = f"{cosign_pkg}~{COSIGN_VERSION}"

        crane_pkg = "crane"
        if CRANE_VERSION != "latest":
            crane_pkg = f"{crane_pkg}~{CRANE_VERSION}"

        grype_pkg = "grype"
        if GRYPE_VERSION != "latest":
            grype_pkg = f"{grype_pkg}~{GRYPE_VERSION}"

        self.builder_ = (
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
            .with_user("root")
            .with_exec(
                [
                    "apk",
                    "add",
                    "--no-cache",
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
                owner="nonroot",
                expand=True,
            )
            .with_mounted_cache(
                "$GRYPE_CACHE_DIR",
                dag.cache_volume("grype-cache"),
                sharing=dagger.CacheSharingMode("SHARED"),
                owner="nonroot",
                expand=True,
            )
            .with_mounted_directory(
                "$SOURCE_DIR",
                source=self.source.filter(include=["images/"]),
                owner="nonroot",
                expand=True,
            )
            .with_user("nonroot")
            .with_workdir("$SOURCE_DIR", expand=True)
        )

        # Inject GitHub Actions secret variables
        # Refer https://docs.github.com/en/actions/writing-workflows/choosing-what-your-workflow-does/store-information-in-variables#default-environment-variables
        if self.github_actions:
            self.builder_ = self.builder_.with_env_variable(
                "CI", "true"
            ).with_env_variable("GITHUB_ACTIONS", "true")
            if self.github_actor:
                self.builder_ = self.builder_.with_env_variable(
                    "CI", "true"
                ).with_env_variable("GITHUB_ACTOR", self.github_actor)
            if self.github_token:
                self.builder_ = self.builder_.with_secret_variable(
                    "GITHUB_TOKEN", self.github_token
                )
            if self.github_oidc_provider_token:
                self.builder_ = self.builder_.with_secret_variable(
                    "ACTIONS_ID_TOKEN_REQUEST_TOKEN", self.github_oidc_provider_token
                )
            if self.github_oidc_provider_url:
                self.builder_ = self.builder_.with_secret_variable(
                    "ACTIONS_ID_TOKEN_REQUEST_URL", self.github_oidc_provider_url
                )
        return self.builder_

    @function
    def with_registry_auth(
        self,
        username: Annotated[str, Doc("Registry username")],
        secret: Annotated[dagger.Secret, Doc("Registry password")],
        address: Annotated[str, Doc("Registry host")] = "ghcr.io",
    ) -> Self:
        """Authenticates with registry (for chaining)"""
        self.container_ = self.container_.with_registry_auth(
            address=address, username=username, secret=secret
        )
        cmd = [
            "sh",
            "-c",
            (
                f"apko login {address}"
                f" --username {username}"
                " --password ${REGISTRY_PASSWORD}"
            ),
        ]
        self.builder_ = (
            self.builder()
            .with_secret_variable("REGISTRY_PASSWORD", secret)
            .with_exec(cmd, use_entrypoint=False)
        )
        return self

    @function
    async def publish(
        self,
        config: Annotated[dagger.File, Doc("APKO config file")],
        tags: Annotated[list[str], Doc("Image tags"), Name("tag")] = (),
        version: Annotated[str, Doc("Image version. Used when no tags provided")] = "",
        platforms: Annotated[
            list[dagger.Platform] | None, Doc("Platforms"), Name("arch")
        ] = None,
        scan: Annotated[bool, Doc("Scan the image for vulnerabilities")] = True,
        scan_fail_on: Annotated[
            str,
            Doc(
                "Fails if a vulnerability is found with a severity >= the given severity"
            ),
        ] = "",
        sign: Annotated[bool, Doc("Sign the image with cosign")] = False,
        cosign_key: Annotated[
            dagger.Secret | None, Doc("Private key to use for image signing")
        ] = None,
        cosign_password: Annotated[
            dagger.Secret | None, Doc("Password used to decrypt the Cosign Private key")
        ] = None,
        identity_token: Annotated[
            dagger.Secret | None, Doc("identity token to use for image signing")
        ] = None,
        oidc_provider: Annotated[
            str, Doc("Specify the provider to get the OIDC token from")
        ] = "",
    ) -> str:
        """Publish the image"""
        # Build the image
        tarball: dagger.File = await self.build(config, platforms=platforms)
        tarball_digest: str = await tarball.digest()

        # Retrieve image title from config
        image_title: str = await self.get_image_title(config)

        # Scan the image for vulnerabilities
        scan_report: dagger.File = None
        if scan:
            scan_report = self.scan_tarball(
                tarball=tarball,
                fail_on=scan_fail_on,
                format_="json",
            )
            await scan_report.contents()

        # Authenticates to the registry when running in GitHub Actions
        if self.github_actor and self.github_token:
            self.with_registry_auth(
                username=self.github_actor,
                secret=self.github_token,
            )

        builder: dagger.Container = self.builder()

        # Publish the image
        if platforms is None:
            platforms = await self.get_platforms(config)
        platform_variants: list[dagger.Container] = []
        digest: str = ""
        full_ref: str = ""

        # Load platform variants form iamge OCI tarball
        for platform in platforms:
            platform_variants.append(dag.container(platform=platform).import_(tarball))
        if not tags:
            # When tags not provided, compute image address.
            repository: str = f"ttl.sh/opopops/wolfi/{image_title}"
            if self.github_actions:
                repository = f"ghcr.io/{self.github_actor}/wolfi/{image_title}"
            if not version:
                version = tarball_digest.split(":")[1][:8]
            tags = [f"{repository}:{version}"]
        full_ref: str = await self.container_.publish(
            address=tags[0], platform_variants=platform_variants
        )

        # Publish the image to the registry
        digest = (
            await builder.with_exec(["crane", "digest", tags[0]]).stdout()
        ).strip()

        # Sign and attest
        if sign:
            builder = builder.with_mounted_directory(
                path="$APKO_SBOM_DIR", source=self.sbom, owner="nonroot", expand=True
            )
            cosign_sign_cmd: list[str] = ["cosign", "sign", "--recursive"]
            cosign_attest_cmd: list[str] = ["cosign", "attest"]
            if cosign_key:
                builder = builder.with_secret_variable("COSIGN_PRIVATE_KEY", cosign_key)
                if cosign_password:
                    builder = builder.with_secret_variable(
                        "COSIGN_PASSWORD", cosign_password
                    )
                cosign_sign_cmd.extend(["--key", "env://COSIGN_PRIVATE_KEY"])
                cosign_attest_cmd.extend(["--key", "env://COSIGN_PRIVATE_KEY"])
            if identity_token:
                builder = builder.with_secret_variable(
                    "COSIGN_IDENTITY_TOKEN", identity_token
                )
                cosign_sign_cmd.extend(["--identity-token", "$COSIGN_IDENTITY_TOKEN"])
                cosign_attest_cmd.extend(["--identity-token", "$COSIGN_IDENTITY_TOKEN"])
            if oidc_provider:
                cosign_sign_cmd.extend(["--oidc-provider", oidc_provider])
                cosign_attest_cmd.extend(["--oidc-provider", oidc_provider])

            # Sign the image with cosign
            await (
                builder.with_exec(
                    ["cosign", "clean", full_ref, "--type", "all", "--force"]
                )
                .with_exec(cosign_sign_cmd + [full_ref], expand=True)
                .stdout()
            )

            # Attest SBOMs
            if len(platforms) > 1:
                # Attest index SBOM
                await builder.with_exec(
                    cosign_attest_cmd
                    + [
                        "--type",
                        "spdxjson",
                        "--predicate",
                        "${APKO_SBOM_DIR}/sbom-index.spdx.json",
                        full_ref,
                    ],
                    expand=True,
                ).stdout()

            # Attest platforms SBOMs
            predicate: str = ""
            for platform in platforms:
                if platform == dagger.Platform("linux/amd64"):
                    predicate = "${APKO_SBOM_DIR}/sbom-x86_64.spdx.json"
                elif platform == dagger.Platform("linux/arm64"):
                    predicate = "${APKO_SBOM_DIR}/sbom-aarch64.spdx.json"
                platform_digest: str = await builder.with_exec(
                    ["crane", "digest", full_ref, "--platform", platform, "--full-ref"],
                    expand=True,
                ).stdout()
                await builder.with_exec(
                    cosign_attest_cmd
                    + [
                        "--type",
                        "spdxjson",
                        "--predicate",
                        predicate,
                        platform_digest.strip(),
                    ],
                    expand=True,
                ).stdout()

            if scan_report:
                # Attest vulnerability report
                await (
                    builder.with_mounted_file(
                        "/tmp/grype-report.json", scan_report, owner="nonroot"
                    )
                    .with_exec(
                        cosign_attest_cmd
                        + [
                            "--type",
                            "vuln",
                            "--predicate",
                            "/tmp/grype-report.json",
                            full_ref,
                        ],
                    )
                    .stdout()
                )

        # Publish other tags
        for tag in tags[1:]:
            await (
                builder.with_exec(["cosign", "clean", tag, "--type", "all", "--force"])
                .with_exec(["cosign", "copy", full_ref, tag, "--force"])
                .stdout()
            )

        if self.github_actions:
            return digest
        return full_ref

    @function
    async def container(
        self,
        config: Annotated[dagger.File, Doc("APKO config file")],
    ) -> dagger.Container:
        """Returns the image container and open an interactive terminal"""
        platform: dagger.Platform = await dag.default_platform()
        tarball: dagger.File = await self.build(config, platforms=[platform])
        return dag.container().import_(source=tarball).terminal()

    @function
    async def scan(
        self,
        config: Annotated[dagger.File, Doc("APKO config file")],
        fail_on: Annotated[
            str,
            Doc(
                "Fails if a vulnerability is found with a severity >= the given severity"
            ),
        ] = "",
        format_: Annotated[str, Doc("Output format"), Name("format")] = "table",
    ) -> str:
        """Scan for vulnerabilities"""
        tarball: dagger.File = await self.build(config)
        return await self.scan_tarball(
            tarball=tarball,
            fail_on=fail_on,
            format_=format_,
        ).contents()

    @function
    async def build(
        self,
        config: Annotated[dagger.File, Doc("APKO config file")],
        platforms: Annotated[
            list[dagger.Platform] | None, Doc("Platforms"), Name("arch")
        ] = None,
    ) -> dagger.File:
        """Builds the image"""
        builder: dagger.Container = self.builder().with_mounted_file(
            "$APKO_CONFIG_FILE", source=config, owner="nonroot", expand=True
        )

        # Retrieve image tag from config
        image_title: str = await self.get_image_title(config)

        cmd: list[str] = [
            "apko",
            "build",
            "$APKO_CONFIG_FILE",
            image_title,
            "$APKO_IMAGE_TARBALL",
            "--cache-dir",
            "$APKO_CACHE_DIR",
            "--sbom-path",
            "$APKO_SBOM_DIR",
        ]
        if platforms:
            for platform in platforms:
                cmd.extend(["--arch", platform.split("/")[1]])
        builder = builder.with_exec(
            cmd,
            expand=True,
        )

        # Save SBOMs
        self.sbom = builder.directory("$APKO_SBOM_DIR", expand=True)

        return builder.file("$APKO_IMAGE_TARBALL", expand=True)
