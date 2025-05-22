from typing import Annotated, Self
from datetime import datetime

import dagger
from dagger import DefaultPath, Doc, Name, dag, function, object_type

from .builder import Builder
from .build import Build
from .config import Config


@object_type
class Wolfi:
    """Wolfi Pipeline"""

    source: dagger.Directory
    builder_: dagger.Container | None
    container_: dagger.Container | None

    github_actions: bool | None
    github_actor: str | None
    github_token: dagger.Secret | None

    @classmethod
    async def create(
        cls,
        source: Annotated[dagger.Directory, DefaultPath("/"), Doc("Source directory")],
        github_actions: Annotated[bool | None, Doc("Enable GitHub Actions")] = False,
        github_actor: Annotated[str | None, Doc("GitHub Actor")] = "",
        github_token: Annotated[dagger.Secret | None, Doc("GitHub Token")] = None,
        github_oidc_provider_token: Annotated[
            dagger.Secret | None, Doc("GitHub OIDC provider Token")
        ] = None,
        github_oidc_provider_url: Annotated[
            dagger.Secret | None, Doc("GitHub OIDC provider URL")
        ] = None,
    ):
        """Constructor"""
        builder: dagger.Container = Builder().container()
        builder = builder.with_mounted_directory(
            "$SOURCE_DIR",
            source=source.filter(include=["images/"]),
            owner=await builder.user(),
            expand=True,
        ).with_workdir("$SOURCE_DIR", expand=True)

        # Inject GitHub Actions secret variables
        # Refer https://docs.github.com/en/actions/writing-workflows/choosing-what-your-workflow-does/store-information-in-variables#default-environment-variables
        if github_actions:
            builder = builder.with_env_variable("CI", "true").with_env_variable(
                "GITHUB_ACTIONS", "true"
            )
            if github_actor:
                builder = builder.with_env_variable("CI", "true").with_env_variable(
                    "GITHUB_ACTOR", github_actor
                )
            if github_token:
                builder = builder.with_secret_variable("GITHUB_TOKEN", github_token)
            if github_oidc_provider_token:
                builder = builder.with_secret_variable(
                    "ACTIONS_ID_TOKEN_REQUEST_TOKEN", github_oidc_provider_token
                )
            if github_oidc_provider_url:
                builder = builder.with_secret_variable(
                    "ACTIONS_ID_TOKEN_REQUEST_URL", github_oidc_provider_url
                )
        return cls(
            source=source,
            github_actions=github_actions,
            github_actor=github_actor,
            github_token=github_token,
            builder_=builder,
            container_=dag.container(),
        )

    async def scan_tarball(
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
        builder: dagger.Container = self.builder_.with_mounted_file(
            "${APKO_IMAGE_TARBALL}",
            source=tarball,
            owner=await self.builder_.user(),
            expand=True,
        )

        cmd: list[str] = [
            "grype",
            "oci-archive:${APKO_IMAGE_TARBALL}",
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
    async def sign(
        self,
        image: Annotated[str, Doc("Image address")],
        annotations: Annotated[
            list[str] | None, Doc("Extra key=value pairs to sign")
        ] = (),
        key: Annotated[
            dagger.Secret | None, Doc("Private key to use for image signing")
        ] = None,
        password: Annotated[
            dagger.Secret | None, Doc("Password used to decrypt the Cosign Private key")
        ] = None,
        oidc_provider: Annotated[
            str, Doc("Specify the provider to get the OIDC token from")
        ] = "",
    ) -> str:
        """Sign the supplied container image"""
        builder: dagger.Container = self.builder_
        cmd: list[str] = ["cosign", "sign", image, "--recursive"]
        for annotation in annotations:
            cmd.extend(["--annotations", annotation])
        if key:
            builder = builder.with_secret_variable("COSIGN_PRIVATE_KEY", key)
            if password:
                builder = builder.with_secret_variable("COSIGN_PASSWORD", password)
            cmd.extend(["--key", "env://COSIGN_PRIVATE_KEY"])
        if oidc_provider:
            cmd.extend(["--oidc-provider", oidc_provider])
        return await builder.with_exec(
            cmd,
            expand=True,
        ).stdout()

    @function
    async def attest(
        self,
        image: Annotated[str, Doc("Image address")],
        predicate: Annotated[dagger.File, Doc("Predicate file")],
        type_: Annotated[str | None, Doc("Predicate type")] = "spdxjson",
        key: Annotated[
            dagger.Secret | None, Doc("Private key to use for image signing")
        ] = None,
        password: Annotated[
            dagger.Secret | None, Doc("Password used to decrypt the Cosign Private key")
        ] = None,
        oidc_provider: Annotated[
            str, Doc("Specify the provider to get the OIDC token from")
        ] = "",
    ) -> str:
        """Attest the supplied container image"""
        builder: dagger.Container = self.builder_
        cmd: list[str] = ["cosign", "attest"]
        if key:
            builder = builder.with_secret_variable("COSIGN_PRIVATE_KEY", key)
            if password:
                builder = builder.with_secret_variable("COSIGN_PASSWORD", password)
            cmd.extend(["--key", "env://COSIGN_PRIVATE_KEY"])
        if oidc_provider:
            cmd.extend(["--oidc-provider", oidc_provider])
        return await (
            builder.with_mounted_file(
                "/tmp/predicate",
                predicate,
                owner=await self.builder_.user(),
            )
            .with_exec(
                cmd
                + [
                    "--type",
                    type_,
                    "--predicate",
                    "/tmp/predicate",
                    image,
                ],
                expand=True,
            )
            .stdout()
        )

    @function
    def builder(self) -> dagger.Container:
        """Returns the builder container"""
        return self.builder_

    @function
    async def config(self, config: dagger.File) -> Config:
        """Returns the Apko config derived from loading a YAML file"""
        config: dagger.File = (
            self.builder_.with_mounted_file(
                "$APKO_CONFIG_FILE",
                source=config,
                owner=await self.builder_.user(),
                expand=True,
            )
            .with_exec(
                ["apko", "show-config", "$APKO_CONFIG_FILE", "--log-level", "ERROR"],
                redirect_stdout="/tmp/config.yaml",
                expand=True,
            )
            .file("/tmp/config.yaml")
        )
        return Config(config=config)

    @function
    def with_registry_auth(
        self,
        username: Annotated[str, Doc("Registry username")],
        secret: Annotated[dagger.Secret, Doc("Registry password")],
        address: Annotated[str, Doc("Registry host")] = "ghcr.io",
    ) -> Self:
        """Authenticates with registry"""
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
        self.builder_ = self.builder_.with_secret_variable(
            "REGISTRY_PASSWORD", secret
        ).with_exec(cmd, use_entrypoint=False)
        return self

    @function
    def with_env_variable(
        self,
        name: Annotated[str, Doc("Name of the environment variable")],
        value: Annotated[str, Doc("Value of the environment variable")],
        expand: Annotated[
            bool | None,
            Doc(
                "Replace “${VAR}” or “$VAR” in the value according to the current environment variables defined in the container"
            ),
        ] = False,
    ) -> Self:
        """Set a new environment variable"""
        self.builder_ = self.builder_.with_env_variable(
            name=name, value=value, expand=expand
        )
        return self

    @function
    def with_secret_variable(
        self,
        name: Annotated[str, Doc("Name of the secret variable")],
        secret: Annotated[dagger.Secret, Doc("Identifier of the secret value")],
    ) -> Self:
        """Set a new environment variable, using a secret value"""
        self.builder_ = self.builder_.with_secret_variable(name=name, secret=secret)
        return self

    @function
    async def with_docker_socket(
        self,
        source: Annotated[
            dagger.Socket,
            Doc(
                "Identifier of the Docker socket to forward (e.g /var/run/docker.sock)"
            ),
        ],
    ) -> Self:
        """Mounts a Docker Unix socket"""
        self.builder_ = self.builder_.with_unix_socket(
            path="/tmp/docker.sock", source=source, owner=await self.builder_.user()
        )
        return self

    @function
    async def publish(
        self,
        config: Annotated[dagger.File, Doc("APKO config file")],
        tags: Annotated[list[str], Doc("Image tags"), Name("tag")] = (),
        version: Annotated[str, Doc("Image version. Used when no tags provided")] = "",
        platforms: Annotated[
            list[dagger.Platform] | None, Doc("Platforms"), Name("platform")
        ] = None,
        scan: Annotated[bool, Doc("Scan the image for vulnerabilities")] = True,
        scan_fail_on: Annotated[
            str,
            Doc(
                "Fails if a vulnerability is found with a severity >= the given severity"
            ),
        ] = "",
        sign: Annotated[bool, Doc("Sign the image with cosign")] = False,
        cosign_annotations: Annotated[
            list[str] | None, Doc("Extra key=value pairs to sign")
        ] = (),
        cosign_key: Annotated[
            dagger.Secret | None, Doc("Private key to use for image signing")
        ] = None,
        cosign_password: Annotated[
            dagger.Secret | None, Doc("Password used to decrypt the Cosign Private key")
        ] = None,
        oidc_provider: Annotated[
            str, Doc("Specify the provider to get the OIDC token from")
        ] = "",
        force: Annotated[
            bool | None, Doc("Force image publishing (invalidate cache)")
        ] = False,
    ) -> str:
        """Publish an image from a YAML config file"""
        # Retrieve the full configuration
        config_: Config = await self.config(config=config)

        if platforms is None:
            platforms = await config_.platforms()

        build: Build = await self.build(config, platforms=platforms)
        build_digest: str = await build.digest()

        # Scan the multi-arch image for vulnerabilities
        scan_reports: dict[dagger.Platform, dagger.File] = {}
        if scan:
            for platform in platforms:
                scan_reports[platform] = await self.scan_tarball(
                    tarball=build.tarball(platform=platform),
                    fail_on=scan_fail_on,
                    format_="json",
                )
                await scan_reports[platform].contents()

        # Authenticates to the registry when running in GitHub Actions
        if self.github_actor and self.github_token:
            self.with_registry_auth(
                username=self.github_actor,
                secret=self.github_token,
            )

        builder: dagger.Container = self.builder_

        digest: str = ""
        full_ref: str = ""

        # When tags not provided, compute image address.
        if not tags:
            # Retrieve image title from config
            image_title: str = await config_.title()
            repository: str = f"ttl.sh/opopops/wolfi/{image_title}"
            if self.github_actions:
                repository = f"ghcr.io/{self.github_actor}/wolfi/{image_title}"
            if not version:
                version = build_digest.split(":")[1][:8]
            tags = [f"{repository}:{version}"]

        # Publish the image
        if force:
            # Cache buster
            self.container_ = self.container_.with_env_variable(
                "CACHEBUSTER", str(datetime.now())
            )
        full_ref: str = await self.container_.publish(
            address=tags[0], platform_variants=build.platform_variants()
        )
        digest = full_ref.split("@")[1]

        # Sign and attest
        if sign:
            builder = builder.with_mounted_directory(
                path="$APKO_SBOM_DIR",
                source=build.as_sbom(),
                owner=await builder.user(),
                expand=True,
            )

            # Clean all existing attestations with cosign
            await builder.with_exec(
                ["cosign", "clean", full_ref, "--type", "all", "--force"]
            ).stdout()
            # Sign the image with cosign
            await self.sign(
                image=full_ref,
                annotations=cosign_annotations,
                key=cosign_key,
                password=cosign_password,
                oidc_provider=oidc_provider,
            )

            # Attest SBOMs
            if len(platforms) > 1:
                # Attest index SBOM
                await self.attest(
                    image=full_ref,
                    predicate=build.sbom(),
                    type_="spdxjson",
                    key=cosign_key,
                    password=cosign_password,
                    oidc_provider=oidc_provider,
                )

            # Attest platforms SBOMs
            for platform in platforms:
                platform_digest: str = await builder.with_exec(
                    ["crane", "digest", full_ref, "--platform", platform, "--full-ref"],
                    expand=True,
                ).stdout()
                await self.attest(
                    image=platform_digest.strip(),
                    predicate=build.sbom(platform),
                    type_="spdxjson",
                    key=cosign_key,
                    password=cosign_password,
                    oidc_provider=oidc_provider,
                )

                if scan_reports:
                    # Attest vulnerability reports
                    await self.attest(
                        image=platform_digest.strip(),
                        predicate=scan_reports[platform],
                        type_="openvex",
                        key=cosign_key,
                        password=cosign_password,
                        oidc_provider=oidc_provider,
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
        """Returns the image container built from a YAML config file"""
        platform: dagger.Platform = await dag.default_platform()
        build: Build = await self.build(config, platforms=[platform])
        return build.container()

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
    ) -> dagger.File:
        """Scan an image built from a YAML config file for vulnerabilities"""
        platform: dagger.Platform = await dag.default_platform()
        build: Build = await self.build(config, platforms=[platform])
        return await self.scan_tarball(
            tarball=build.tarball(),
            fail_on=fail_on,
            format_=format_,
        )

    @function
    async def scan_image(
        self,
        address: Annotated[str, Doc("Address of the image to scan")],
        fail_on: Annotated[
            str,
            Doc(
                "Fails if a vulnerability is found with a severity >= the given severity"
            ),
        ] = "",
        format_: Annotated[str, Doc("Output format"), Name("format")] = "table",
    ) -> dagger.File:
        """Scan an image for vulnerabilities"""
        tarball: dagger.File = dag.container().from_(address=address).as_tarball()
        return await self.scan_tarball(
            tarball=tarball,
            fail_on=fail_on,
            format_=format_,
        )

    @function
    async def build(
        self,
        config: Annotated[dagger.File, Doc("APKO config file")],
        platforms: Annotated[
            list[dagger.Platform] | None, Doc("Platforms"), Name("platform")
        ] = None,
    ) -> Build:
        """Builds an image from a YAML config file and returns it as a tarball"""
        # Retrieve the full configuration
        config_: Config = await self.config(config=config)

        builder: dagger.Container = self.builder_.with_mounted_file(
            "$APKO_CONFIG_FILE",
            source=config,
            owner=await self.builder_.user(),
            expand=True,
        )

        # Retrieve image tag from config
        image_title: str = await config_.title()

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
        else:
            # Retrieves platforms from config
            platforms = await config_.platforms()

        builder = builder.with_exec(
            cmd,
            expand=True,
        )

        tarball: dagger.File = builder.file("$APKO_IMAGE_TARBALL", expand=True)
        sbom: dagger.Directory = builder.directory("$APKO_SBOM_DIR", expand=True)

        return Build(tarball_=tarball, sbom_=sbom, platforms=platforms)
