import yaml
import dagger
from dagger import function, object_type


@object_type
class Config:
    """Wolfi Config"""

    config: dagger.File

    @function
    async def title(self) -> str:
        """Returns the image title from config"""
        config_dict: dict = yaml.safe_load(await self.config.contents())
        return config_dict["annotations"]["org.opencontainers.image.title"]

    @function
    async def platforms(self) -> list[dagger.Platform]:
        """Returns the platforms"""
        platforms: list[dagger.Platform] = []
        config_dict: dict = yaml.safe_load(await self.config.contents())
        archs: list[str] = config_dict.get("archs", [])
        for arch in archs:
            if arch in ["amd64", "x86_64"]:
                platforms.append(dagger.Platform("linux/amd64"))
            elif arch in ["arm64", "aarch64"]:
                platforms.append(dagger.Platform("linux/arm64"))
            else:
                continue
        return platforms
