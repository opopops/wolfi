import random
from typing import Annotated, Self
from datetime import datetime

import dagger
from dagger import DefaultPath, Doc, Name, dag, function, object_type

UUID: str = random.randrange(10**8)


@object_type
class Wolfi:
    """Build Wolfi base images"""

    source: dagger.Directory

    apko_: dagger.Apko
    cosign_: dagger.Cosign
    crane_: dagger.Crane
    grype_: dagger.Grype

    container_: dagger.Container
    platform_variants_: list[dagger.Platform] | None = None
    sbom_: dagger.Directory | None = None

    github_actions: bool | None
    github_actor: str | None
    github_repository: str | None
    github_repository_owner: str | None
    github_token: dagger.Secret | None

    @classmethod
    async def create(
        cls,
        source: Annotated[dagger.Directory, DefaultPath("/"), Doc("Source directory")],
        github_actions: Annotated[bool | None, Doc("Enable GitHub Actions")] = False,
        github_actor: Annotated[str | None, Doc("GitHub Actor")] = "",
        github_repository: Annotated[
            str | None, Doc("The owner and repository name")
        ] = "",
        github_repository_owner: Annotated[
            str | None, Doc("The repository owner's username")
        ] = "",
        github_token: Annotated[dagger.Secret | None, Doc("GitHub Token")] = None,
        github_oidc_provider_token: Annotated[
            dagger.Secret | None, Doc("GitHub OIDC provider Token")
        ] = None,
        github_oidc_provider_url: Annotated[
            dagger.Secret | None, Doc("GitHub OIDC provider URL")
        ] = None,
    ):
        """Constructor"""
        apko: dagger.Apko = dag.apko(
            source=source.filter(include=["images/"], exclude=["**.md"])
        )
        cosign: dagger.Cosign = dag.cosign()
        crane: dagger.Crane = dag.crane()
        grype: dagger.Grype = dag.grype()
        # Inject GitHub Actions secret variables
        # Refer https://docs.github.com/en/actions/writing-workflows/choosing-what-your-workflow-does/store-information-in-variables#default-environment-variables
        if github_actions:
            cosign = cosign.with_env_variable("CI", "true").with_env_variable(
                "GITHUB_ACTIONS", "true"
            )
            if github_actor:
                cosign = cosign.with_env_variable("GITHUB_ACTOR", github_actor)
            if github_token:
                cosign = cosign.with_secret_variable("GITHUB_TOKEN", github_token)
            if github_oidc_provider_token:
                cosign = cosign.with_secret_variable(
                    "ACTIONS_ID_TOKEN_REQUEST_TOKEN", github_oidc_provider_token
                )
            if github_oidc_provider_url:
                cosign = cosign.with_secret_variable(
                    "ACTIONS_ID_TOKEN_REQUEST_URL", github_oidc_provider_url
                )
        return cls(
            source=source.filter(include=["images/"], exclude=["**.md"]),
            github_actions=github_actions,
            github_actor=github_actor,
            github_repository=github_repository,
            github_repository_owner=github_repository_owner,
            github_token=github_token,
            apko_=apko,
            cosign_=cosign,
            crane_=crane,
            grype_=grype,
            container_=dag.container(),
        )

    def _sbom(
        self, platform: Annotated[dagger.Platform | None, Doc("Platform")] = None
    ) -> dagger.File:
        """Returns the SBOM file for the specified platform (index if not specified)"""
        if platform is not None:
            if platform == dagger.Platform("linux/amd64"):
                return self.sbom_.file("sbom-x86_64.spdx.json")
            return self.sbom_.file("sbom-aarch64.spdx.json")
        return self.sbom_.file("sbom-index.spdx.json")

    @function
    def apko(self) -> dagger.Container:
        """Return the apko container"""
        return self.apko_.container()

    @function
    def cosign(self) -> dagger.Container:
        """Return the cosign container"""
        return self.cosign_.container()

    @function
    def crane(self) -> dagger.Container:
        """Return the crane container"""
        return self.crane_.container()

    @function
    def grype(self) -> dagger.Container:
        """Return the grype container"""
        return self.grype_.container()

    @function
    async def config(self, config: dagger.File) -> dagger.File:
        """Return the Apko config derived from loading a YAML file"""
        return self.apko_.config(config=config).file()

    @function
    def with_registry_auth(
        self,
        username: Annotated[str, Doc("Registry username")],
        secret: Annotated[dagger.Secret, Doc("Registry password")],
        address: Annotated[str, Doc("Registry host")] = "ghcr.io",
    ) -> Self:
        """Authenticate with registry"""
        self.container_ = self.container_.with_registry_auth(
            address=address, username=username, secret=secret
        )
        self.apko_ = self.apko_.with_registry_auth(
            address=address, username=username, secret=secret
        )
        docker_config: dagger.File = self.apko_.docker_config()
        self.cosign_ = self.cosign_.with_docker_config(docker_config)
        self.crane_ = self.crane_.with_docker_config(docker_config)
        self.grype_ = self.grype_.with_docker_config(docker_config)
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
        self.apko_ = self.apko_.with_env_variable(name=name, value=value, expand=expand)
        self.cosign_ = self.cosign_.with_env_variable(
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
        self.apko_ = self.apko_.with_secret_variable(name=name, secret=secret)
        self.cosign_ = self.cosign_.with_secret_variable(name=name, secret=secret)
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
        self.apko_ = self.apko_.with_unix_socket(source=source)
        return self

    @function
    async def publish(
        self,
        image: Annotated[str, Doc("Image name")],
        variant: Annotated[str | None, Doc("Image variant")] = "prod",
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
        if platforms is None:
            platforms = [await dag.default_platform()]

        build: dagger.Directory = await self.build(
            image=image, variant=variant, platforms=platforms
        )
        build_tarball: dagger.File = build.file("image.tar")
        build_digest: str = await build.digest()

        # Scan the multi-arch image for vulnerabilities
        scan_reports: dict[dagger.Platform, dagger.File] = {}
        if scan:
            for platform in platforms:
                scan_reports[platform] = self.grype_.scan_file(
                    source=dag.container(platform=platform)
                    .import_(build_tarball)
                    .as_tarball(),
                    source_type="oci-archive",
                    severity=scan_fail_on,
                    output_format="json",
                )
                await scan_reports[platform].contents()

        # Authenticates to the registry when running in GitHub Actions
        if self.github_actor and self.github_token:
            self.with_registry_auth(
                username=self.github_actor,
                secret=self.github_token,
            )

        digest: str = ""
        full_ref: str = ""

        # When tags not provided, compute image address.
        if not tags:
            # Retrieve image title from config
            registry: str = "ttl.sh"
            repository: str = f"{UUID}/{image}"
            if self.github_actions:
                registry: str = "ghcr.io"
                repository = f"{self.github_repository.lower()}/{image}"
            if not version:
                version = build_digest.split(":")[1][:8]
            tags = [f"{registry}/{repository}:{version}"]

        # Publish the image
        if force:
            # Cache buster
            self.container_ = self.container_.with_env_variable(
                "CACHEBUSTER", str(datetime.now())
            )

        full_ref: str = await self.container_.publish(
            address=tags[0], platform_variants=self.platform_variants_
        )
        digest = full_ref.split("@")[1]

        # Sign and attest
        if sign:
            # Clean all existing attestations with cosign
            await self.cosign_.clean(full_ref)

            # Sign the image with cosign
            await self.cosign_.sign(
                image=full_ref,
                annotations=cosign_annotations,
                private_key=cosign_key,
                password=cosign_password,
                oidc_provider=oidc_provider,
                recursive=True,
            )

            # Attest SBOMs
            if len(platforms) > 1:
                # Attest index SBOM
                await self.cosign_.attest(
                    image=full_ref,
                    predicate=self._sbom(),
                    type_="spdxjson",
                    private_key=cosign_key,
                    password=cosign_password,
                    oidc_provider=oidc_provider,
                )

            # Attest platforms SBOMs
            for platform in platforms:
                platform_digest: str = await self.crane_.digest(
                    full_ref, platform=platform, full_ref=True
                )
                await self.cosign_.attest(
                    image=platform_digest.strip(),
                    predicate=self._sbom(platform),
                    type_="spdxjson",
                    private_key=cosign_key,
                    password=cosign_password,
                    oidc_provider=oidc_provider,
                )

                if scan_reports:
                    # Attest vulnerability reports
                    await self.cosign_.attest(
                        image=platform_digest.strip(),
                        predicate=scan_reports[platform],
                        type_="openvex",
                        private_key=cosign_key,
                        password=cosign_password,
                        oidc_provider=oidc_provider,
                    )

        # Publish other tags
        for tag in tags[1:]:
            await self.cosign_.copy(source=full_ref, destination=tag, force=True)

        if self.github_actions:
            return digest
        return full_ref

    @function
    async def container(
        self,
        image: Annotated[str, Doc("Image name")],
        variant: Annotated[str | None, Doc("Image variant")] = "prod",
    ) -> dagger.Container:
        """Return the image container built from a YAML config file"""
        build: dagger.Directory = await self.build(image=image, variant=variant)
        return (
            dag.container().import_(build.file("image.tar")).with_workdir(f"/{image}")
        )

    @function
    def scan_image(
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
        return self.grype_.scan_image(
            source=address, severity=fail_on, output_format=format_
        )

    @function
    async def scan(
        self,
        image: Annotated[str, Doc("Image name")],
        variant: Annotated[str | None, Doc("Image variant")] = "prod",
        fail_on: Annotated[
            str,
            Doc(
                "Fails if a vulnerability is found with a severity >= the given severity"
            ),
        ] = "",
        format_: Annotated[str, Doc("Output format"), Name("format")] = "table",
    ) -> dagger.File:
        """Scan an image built from a YAML config file for vulnerabilities"""
        build: dagger.Directory = await self.build(image=image, variant=variant)
        return self.grype_.scan_file(
            build.file("image.tar"),
            source_type="oci-archive",
            severity=fail_on,
            output_format=format_,
        )

    @function
    async def sbom(
        self,
        image: Annotated[str, Doc("Image name")],
        variant: Annotated[str | None, Doc("Image variant")] = "prod",
    ) -> dagger.File:
        """Return the SBOM for the sepecified image config file"""
        await self.build(image=image, variant=variant)
        return self._sbom(await dag.default_platform())

    @function
    async def build(
        self,
        image: Annotated[str, Doc("Image name")],
        variant: Annotated[str | None, Doc("Image variant")] = "prod",
        platforms: Annotated[
            list[dagger.Platform] | None, Doc("Platforms"), Name("platform")
        ] = None,
    ) -> dagger.Directory:
        """Build an image from a YAML config file and returns it as a directory"""
        config: dagger.File = self.apko_.source().file(f"images/{image}/{variant}.yaml")
        build: dagger.ApkoBuild = self.apko_.build(
            config=config,
            tag=f"{image}-{variant}",
            arch=platforms,
        )
        for platform in await build.platforms():
            if platform == await dag.default_platform():
                self.container_ = self.container_.import_(build.tarball())
            else:
                self.platform_variants_.append(
                    dag.container(platform=platform).import_(build.tarball())
                )
            self.sbom_ = build.sbom()
        return build.as_directory()
