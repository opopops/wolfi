from typing import Annotated
import dagger
from dagger import Doc, dag, function, object_type


@object_type
class Build:
    """Wolfi Build module"""

    tarball: Annotated[dagger.File, Doc("apko tarball")]
    sbom: Annotated[dagger.Directory, Doc("SBOM directory")]
    platforms: Annotated[list[dagger.Platform], Doc("Platforms")]

    @function
    async def digest(self) -> str:
        """Returns the build digest"""
        return await self.tarball.digest()

    @function
    def container(
        self, platform: Annotated[dagger.Platform | None, Doc("Platform")] = None
    ) -> dagger.Container:
        """Returns the container"""
        return dag.container(platform=platform).import_(self.tarball)

    @function
    def platform_variants(self) -> list[dagger.Container]:
        """Returns plarform variants"""
        platform_variants: list[dagger.Platform] = []
        for platform in self.platforms:
            platform_variants.append(
                dag.container(platform=platform).import_(self.tarball)
            )
        return platform_variants

    @function
    def platform_sbom(
        self, platform: Annotated[dagger.Platform | None, Doc("Platform")] = None
    ) -> dagger.File:
        """Return the SBOM for the specified platform (index if not specified)"""
        if platform is not None:
            if platform == dagger.Platform("linux/amd64"):
                return self.sbom.file("sbom-x86_64.spdx.json")
            return self.sbom.file("sbom-aarch64.spdx.json")
        return self.sbom.file("sbom-index.spdx.json")

    @function
    def as_tarball(
        self,
        platform: Annotated[dagger.Platform | None, Doc("Platform")] = None,
    ) -> dagger.File:
        """Package the build state as an OCI image, and return it as a tar archive"""
        platform_variants: list[dagger.Platform] = []
        if platform is None:
            return self.tarball
        return (
            dag.container(platform=platform)
            .import_(self.tarball)
            .as_tarball(platform_variants=platform_variants)
        )

    @function
    def as_sbom(self) -> dagger.Directory:
        """Returns the build SBOMs"""
        return self.sbom

    @function
    def as_directory(self) -> dagger.Directory:
        """Returns the build state as directory, including tarball and SBOMs"""
        return (
            dag.directory()
            .with_file("image.tar", self.as_tarball())
            .with_directory("sbom", self.sbom)
        )
