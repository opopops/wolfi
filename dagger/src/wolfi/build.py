from typing import Annotated
import dagger
from dagger import Doc, dag, function, object_type


@object_type
class Build:
    """Wolfi Build"""

    tarball_: dagger.File
    sbom_: dagger.Directory
    platforms: list[dagger.Platform]

    @function
    def as_tarball(
        self,
    ) -> dagger.File:
        """Returns the OCI tarball"""
        return self.tarball_

    @function
    def as_sbom(self) -> dagger.Directory:
        """Returns the build SBOMs"""
        return self.sbom_

    @function
    def as_directory(self) -> dagger.Directory:
        """Returns the build state as directory, including tarball and SBOMs"""
        return (
            dag.directory()
            .with_file("image.tar", self.as_tarball())
            .with_directory("sbom", self.sbom_)
        )

    @function
    async def digest(self) -> str:
        """Returns the build digest"""
        return await self.tarball_.digest()

    @function
    def sbom(
        self, platform: Annotated[dagger.Platform | None, Doc("Platform")] = None
    ) -> dagger.File:
        """Return the SBOM for the specified platform (index if not specified)"""
        if platform is not None:
            if platform == dagger.Platform("linux/amd64"):
                return self.sbom_.file("sbom-x86_64.spdx.json")
            return self.sbom_.file("sbom-aarch64.spdx.json")
        return self.sbom_.file("sbom-index.spdx.json")

    @function
    def container(
        self, platform: Annotated[dagger.Platform | None, Doc("Platform")] = None
    ) -> dagger.Container:
        """Returns the container for the specified platform"""
        return dag.container(platform=platform).import_(self.tarball_)

    @function
    def tarball(
        self, platform: Annotated[dagger.Platform | None, Doc("Platform")] = None
    ) -> dagger.File:
        """Returns the container for the specified platform"""
        return self.container(platform=platform).as_tarball()

    @function
    def platform_variants(self) -> list[dagger.Container]:
        """Returns plarform variants"""
        platform_variants: list[dagger.Platform] = []
        for platform in self.platforms:
            platform_variants.append(
                dag.container(platform=platform).import_(self.tarball_)
            )
        return platform_variants
