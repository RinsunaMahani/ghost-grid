"""Sector profiles registry and loader for GhostGrid."""
from typing import Dict, Type
from ghostgrid.core.identity import SiteIdentity
from ghostgrid.profiles.base import SectorProfile
from ghostgrid.profiles.water.simulation import WaterProfile
from ghostgrid.profiles.power.simulation import PowerProfile

PROFILE_REGISTRY: Dict[str, Type[SectorProfile]] = {
    "water": WaterProfile,
    "power": PowerProfile,
}


def create_profile(sector: str, identity: SiteIdentity, noise_amplitude: float = 0.02) -> SectorProfile:
    """Instantiate the physical simulation profile for the selected sector."""
    sec = sector.lower()
    profile_cls = PROFILE_REGISTRY.get(sec, WaterProfile)
    return profile_cls(identity, noise_amplitude=noise_amplitude)


__all__ = ["SectorProfile", "WaterProfile", "PowerProfile", "create_profile", "PROFILE_REGISTRY"]
