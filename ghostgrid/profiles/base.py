"""Base profile interfaces and registry for GhostGrid sector physics."""
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from ghostgrid.core.identity import SiteIdentity, TagDefinition


class SectorProfile(ABC):
    """Abstract base class for all physical sector simulations (Water, Power, etc.)."""

    def __init__(self, identity: SiteIdentity, noise_amplitude: float = 0.02):
        self.identity = identity
        self.noise_amplitude = noise_amplitude

    @property
    @abstractmethod
    def sector_name(self) -> str:
        """Name of the infrastructure sector (e.g. 'water', 'power')."""
        pass

    @abstractmethod
    def initialize_state(self) -> Dict[str, Any]:
        """Generate initial physical state dictionary mapping tag names to current values."""
        pass

    @abstractmethod
    def step(self, dt: float, current_state: Dict[str, Any]) -> Dict[str, Any]:
        """Perform a physics integration step (dt in seconds) and return updated state.
        
        Must preserve cross-signal consistency (e.g. open breaker -> zero current;
        pump off -> zero flow) and apply realistic stochastic sensor noise.
        """
        pass

    @abstractmethod
    def handle_write(self, tag_name: str, new_value: Any, current_state: Dict[str, Any]) -> Dict[str, Any]:
        """Handle attacker/operator write actions and compute physical side effects."""
        pass
