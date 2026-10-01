"""Process state engine for GhostGrid.

Maintains live shared telemetry across physical simulation ticks and Modbus requests.
Guarantees sub-millisecond thread-safe access so that the Modbus protocol frontend
never waits on disk I/O, an LLM, or complex computation.
Strict address checking: returns None for unmapped addresses so Modbus returns 0x02.
"""
import asyncio
import json
import logging
import os
import threading
import time
from typing import Dict, List, Optional, Tuple, Any, Callable
from ghostgrid.core.identity import SiteIdentity, RegisterType, TagDefinition
from ghostgrid.profiles.base import SectorProfile

logger = logging.getLogger("ghostgrid.state")


class StateEngine:
    """Central state coordinator that bridges physical profiles and protocol registers."""

    def __init__(
        self,
        identity: SiteIdentity,
        profile: SectorProfile,
        tick_interval: float = 1.0,
        write_callback: Optional[Callable[[str, Any, TagDefinition], None]] = None,
        auto_recovery: bool = False,
        state_file_path: Optional[str] = None,
        state_file: Optional[str] = None,
    ):
        self.identity = identity
        self.profile = profile
        self.tick_interval = tick_interval
        self.write_callback = write_callback
        self.auto_recovery = auto_recovery
        self.state_file_path = state_file_path or state_file

        self._lock = threading.RLock()
        self._running = False
        self._thread: Optional[threading.Thread] = None

        # Live values keyed by tag name
        self._state: Dict[str, Any] = self.profile.initialize_state()

        # Fast lookup mapping: (RegisterType, address) -> TagDefinition
        self._reg_map: Dict[Tuple[RegisterType, int], TagDefinition] = {}
        for tag in self.identity.tags.values():
            self._reg_map[(tag.reg_type, tag.address)] = tag

        # Track timestamps for auto-recovery if enabled
        self._trip_timestamps: Dict[str, float] = {}

    def start(self):
        """Start the background physical simulation tick thread."""
        with self._lock:
            if self._running:
                return
            self._running = True
            self._thread = threading.Thread(target=self._tick_loop, daemon=True, name="GhostGrid-Physics")
            self._thread.start()
            logger.info("Physical simulation engine started (tick=%.2fs)", self.tick_interval)

    def stop(self):
        """Stop the simulation tick thread."""
        with self._lock:
            self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
            logger.info("Physical simulation engine stopped")

    def _export_state_file(self):
        """Periodically write live state to JSON in the background for dashboard synchronization."""
        if not self.state_file_path:
            return
        try:
            snapshot = dict(self._state)
            snapshot["_sector"] = self.identity.sector
            snapshot["_site_name"] = self.identity.site_name
            snapshot["_timestamp"] = time.time()
            tmp_path = self.state_file_path + ".tmp"
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(snapshot, f, indent=2)
            os.replace(tmp_path, self.state_file_path)
        except Exception:
            pass

    def _tick_loop(self):
        last_mono = time.monotonic()
        while self._running:
            try:
                now_mono = time.monotonic()
                dt = min(2.0, now_mono - last_mono)
                last_mono = now_mono

                with self._lock:
                    self._state = self.profile.step(dt, self._state)

                    if self.auto_recovery:
                        now = time.time()
                        for tag_name, val in list(self._state.items()):
                            if "TRIP" in tag_name and val == 1:
                                if tag_name not in self._trip_timestamps:
                                    self._trip_timestamps[tag_name] = now
                                elif now - self._trip_timestamps[tag_name] > 30.0:
                                    self._state[tag_name] = 0
                                    del self._trip_timestamps[tag_name]

                # State file export occurs strictly in background loop, NEVER on request path
                self._export_state_file()
                time.sleep(self.tick_interval)
            except Exception as e:
                logger.error("Error in physics simulation step: %s", e, exc_info=True)
                time.sleep(1.0)

    def get_snapshot(self) -> Dict[str, Any]:
        """Return a copy of the current physical state."""
        with self._lock:
            return dict(self._state)

    def get_tag_value(self, tag_name: str) -> Optional[Any]:
        """Fetch current engineering value for a specific tag."""
        with self._lock:
            return self._state.get(tag_name)

    def update_tag_value(self, tag_name: str, value: Any):
        """Directly adjust a tag value (used by Director or manual override)."""
        with self._lock:
            self._state = self.profile.handle_write(tag_name, value, self._state)

    # --------------------------------------------------------------------------
    # Modbus Protocol Accessors (Sub-millisecond latency, zero disk I/O)
    # --------------------------------------------------------------------------

    def read_coils(self, start_address: int, count: int) -> Tuple[Optional[List[int]], Optional[List[Optional[TagDefinition]]]]:
        """Read 1-bit coils (0x01). Returns (None, None) if any address is unmapped."""
        values = []
        tags = []
        with self._lock:
            for addr in range(start_address, start_address + count):
                tag = self._reg_map.get((RegisterType.COIL, addr))
                if not tag:
                    return None, None
                tags.append(tag)
                val = 1 if self._state.get(tag.name, 0) else 0
                values.append(val)
        return values, tags

    def read_discrete_inputs(self, start_address: int, count: int) -> Tuple[Optional[List[int]], Optional[List[Optional[TagDefinition]]]]:
        """Read 1-bit discrete inputs (0x02). Returns (None, None) if any address is unmapped."""
        values = []
        tags = []
        with self._lock:
            for addr in range(start_address, start_address + count):
                tag = self._reg_map.get((RegisterType.DISCRETE_INPUT, addr))
                if not tag:
                    return None, None
                tags.append(tag)
                val = 1 if self._state.get(tag.name, 0) else 0
                values.append(val)
        return values, tags

    def read_input_registers(self, start_address: int, count: int) -> Tuple[Optional[List[int]], Optional[List[Optional[TagDefinition]]]]:
        """Read 16-bit analog input registers (0x04). Returns (None, None) if any address is unmapped."""
        values = []
        tags = []
        with self._lock:
            for addr in range(start_address, start_address + count):
                tag = self._reg_map.get((RegisterType.INPUT_REGISTER, addr))
                if not tag:
                    return None, None
                tags.append(tag)
                raw_val = int(self._state.get(tag.name, 0)) & 0xFFFF
                values.append(raw_val)
        return values, tags

    def read_holding_registers(self, start_address: int, count: int) -> Tuple[Optional[List[int]], Optional[List[Optional[TagDefinition]]]]:
        """Read 16-bit holding registers (0x03). Returns (None, None) if any address is unmapped."""
        values = []
        tags = []
        with self._lock:
            for addr in range(start_address, start_address + count):
                tag = self._reg_map.get((RegisterType.HOLDING_REGISTER, addr))
                if not tag:
                    return None, None
                tags.append(tag)
                raw_val = int(self._state.get(tag.name, 0)) & 0xFFFF
                values.append(raw_val)
        return values, tags

    def write_coil(self, address: int, value: int) -> Optional[TagDefinition]:
        """Write single coil (0x05). Returns None if address is unmapped or read-only."""
        val_bool = 1 if value != 0 else 0
        tag = None
        with self._lock:
            tag = self._reg_map.get((RegisterType.COIL, address))
            if not tag or tag.read_only:
                return None
            self._state = self.profile.handle_write(tag.name, val_bool, self._state)

        if self.write_callback and tag:
            self.write_callback(tag.name, val_bool, tag)
        return tag

    def write_holding_register(self, address: int, value: int) -> Optional[TagDefinition]:
        """Write single holding register (0x06). Returns None if address is unmapped or read-only."""
        val_uint16 = int(value) & 0xFFFF
        tag = None
        with self._lock:
            tag = self._reg_map.get((RegisterType.HOLDING_REGISTER, address))
            if not tag or tag.read_only:
                return None
            self._state = self.profile.handle_write(tag.name, val_uint16, self._state)

        if self.write_callback and tag:
            self.write_callback(tag.name, val_uint16, tag)
        return tag

    def write_multiple_coils(self, start_address: int, values: List[int]) -> Optional[List[TagDefinition]]:
        """Write multiple coils (0x0F). Returns None if any address is unmapped or read-only."""
        written_tags = []
        with self._lock:
            for i, val in enumerate(values):
                addr = start_address + i
                tag = self._reg_map.get((RegisterType.COIL, addr))
                if not tag or tag.read_only:
                    return None
                written_tags.append(tag)

            for tag, val in zip(written_tags, values):
                val_bool = 1 if val != 0 else 0
                self._state = self.profile.handle_write(tag.name, val_bool, self._state)

        if self.write_callback:
            for tag, val in zip(written_tags, values):
                self.write_callback(tag.name, val, tag)
        return written_tags

    def write_multiple_holding_registers(self, start_address: int, values: List[int]) -> Optional[List[TagDefinition]]:
        """Write multiple holding registers (0x10). Returns None if any address is unmapped or read-only."""
        written_tags = []
        with self._lock:
            for i, val in enumerate(values):
                addr = start_address + i
                tag = self._reg_map.get((RegisterType.HOLDING_REGISTER, addr))
                if not tag or tag.read_only:
                    return None
                written_tags.append(tag)

            for tag, val in zip(written_tags, values):
                w_val = int(val) & 0xFFFF
                self._state = self.profile.handle_write(tag.name, w_val, self._state)

        if self.write_callback:
            for tag, val in zip(written_tags, values):
                self.write_callback(tag.name, val, tag)
        return written_tags
