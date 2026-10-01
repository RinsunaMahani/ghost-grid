"""Power sector physics simulation for GhostGrid.

Models a South African 88kV/11kV electrical distribution/transmission substation:
- 50.00 Hz nominal national grid frequency
- Calibrated 3-phase Active Power (46.2 MW baseline matching P = sqrt(3)*V*I*pf)
- Buchholz alarm triggered by internal electrical faults (NOT temperature)
- Transformer winding heating driven by I^2 thermal dynamics
- Cross-signal consistency (tripped breaker -> instantaneous zero current)
"""
import math
import random
from typing import Dict, Any
from ghostgrid.profiles.base import SectorProfile
from ghostgrid.core.identity import SiteIdentity


class PowerProfile(SectorProfile):
    """Substation and power grid physics simulator with calibrated electrical math."""

    def __init__(self, identity: SiteIdentity, noise_amplitude: float = 0.02):
        super().__init__(identity, noise_amplitude)
        self.rng = random.Random()
        # Electrical baseline parameters
        self.nominal_freq_hz = 50.00
        self.current_freq_hz = 50.02
        self.nominal_bus_kv = 88.0
        # Calibrated baseline feeder currents so P = sqrt(3)*88*330*0.92/1000 = 46.2 MW exactly
        self.feeder_1_base_amps = 175.0
        self.feeder_2_base_amps = 155.0
        self.power_factor = 0.92

        # Continuous thermal and voltage state
        self.transformer_temp_c: float = 58.4
        self.bus_voltage_kv: float = 88.3

        temp_tag = self.identity.tags.get("TRANSFORMER_TEMP_C")
        if temp_tag and temp_tag.default_value:
            self.transformer_temp_c = float(temp_tag.default_value) * temp_tag.scale_factor
        v_tag = self.identity.tags.get("BUS_VOLTAGE_KV")
        if v_tag and v_tag.default_value:
            self.bus_voltage_kv = float(v_tag.default_value) * v_tag.scale_factor
        f1_tag = self.identity.tags.get("FEEDER_1_CURRENT_A")
        if f1_tag and f1_tag.default_value:
            self.feeder_1_base_amps = float(f1_tag.default_value)
        f2_tag = self.identity.tags.get("FEEDER_2_CURRENT_A")
        if f2_tag and f2_tag.default_value:
            self.feeder_2_base_amps = float(f2_tag.default_value)

    @property
    def sector_name(self) -> str:
        return "power"

    def initialize_state(self) -> Dict[str, Any]:
        state = {}
        for tag_name, tag in self.identity.tags.items():
            state[tag_name] = tag.default_value
        return state

    def _sample_heavy_tailed_noise(self) -> float:
        """Sample from non-Gaussian heavy-tailed distribution (kurtosis > 3)."""
        if self.noise_amplitude <= 0:
            return 0.0
        if self.rng.random() < 0.15:
            scale = 0.06
            u = self.rng.random() - 0.5
            return -scale * math.copysign(1.0, u) * math.log(1.0 - 2.0 * abs(u) + 1e-12)
        else:
            return self.rng.gauss(0, 0.015)

    def step(self, dt: float, current_state: Dict[str, Any]) -> Dict[str, Any]:
        """Integrate 1 step of electrical physics, frequency dynamics, and breaker states."""
        state = dict(current_state)

        # 1. Breaker commands & setpoints
        f1_cmd = bool(state.get("FEEDER_1_CB_CMD", 1))
        f2_cmd = bool(state.get("FEEDER_2_CB_CMD", 1))
        cap_cmd = bool(state.get("CAPACITOR_BANK_CMD", 1))
        tap_pos = int(state.get("VOLTAGE_REGULATOR_TAP", 8))
        oc_pickup = float(state.get("OVERCURRENT_PICKUP_A", 450))

        # 2. Grid Frequency Simulation (Ornstein-Uhlenbeck)
        theta = 0.25
        drift = theta * (self.nominal_freq_hz - self.current_freq_hz) * dt
        shock = self._sample_heavy_tailed_noise() * math.sqrt(dt)
        self.current_freq_hz += drift + shock
        self.current_freq_hz = max(49.10, min(50.90, self.current_freq_hz))

        state["GRID_FREQUENCY_HZ"] = int(round(self.current_freq_hz * 100))
        state["GRID_SYNC_CHECK"] = 1 if (49.50 <= self.current_freq_hz <= 50.50) else 0

        # 3. Bus Voltage based on tap changer (VOLTAGE_REGULATOR_TAP)
        tap_delta_pct = (tap_pos - 8) * 0.0125
        v_noise = self.rng.gauss(0, 0.003) if self.noise_amplitude > 0 else 0.0
        self.bus_voltage_kv = self.nominal_bus_kv * (1.0 + tap_delta_pct + v_noise)
        state["BUS_VOLTAGE_KV"] = int(round(self.bus_voltage_kv * 10))

        # 4. Feeder Phase Currents
        if f1_cmd:
            i1_noise = self.rng.gauss(0, self.noise_amplitude) if self.noise_amplitude > 0 else 0.0
            f1_amps = max(0.0, self.feeder_1_base_amps * (1.0 + i1_noise))
            if f1_amps > oc_pickup:
                # Overcurrent protection trip
                f1_cmd = False
                f1_amps = 0.0
                state["FEEDER_1_CB_CMD"] = 0
        else:
            f1_amps = 0.0

        if f2_cmd:
            i2_noise = self.rng.gauss(0, self.noise_amplitude) if self.noise_amplitude > 0 else 0.0
            f2_amps = max(0.0, self.feeder_2_base_amps * (1.0 + i2_noise))
            if f2_amps > oc_pickup:
                f2_cmd = False
                f2_amps = 0.0
                state["FEEDER_2_CB_CMD"] = 0
        else:
            f2_amps = 0.0

        state["FEEDER_1_CB_STATUS"] = 1 if f1_cmd else 0
        state["FEEDER_2_CB_STATUS"] = 1 if f2_cmd else 0
        state["FEEDER_1_CURRENT_A"] = int(round(f1_amps))
        state["FEEDER_2_CURRENT_A"] = int(round(f2_amps))

        # 5. True 3-phase Active & Reactive Power Calculations
        total_amps = f1_amps + f2_amps
        p_mw = (math.sqrt(3.0) * self.bus_voltage_kv * total_amps * self.power_factor) / 1000.0
        state["ACTIVE_POWER_MW"] = int(round(p_mw * 10))

        sin_phi = math.sqrt(1.0 - (self.power_factor ** 2))
        q_raw_mvar = (math.sqrt(3.0) * self.bus_voltage_kv * total_amps * sin_phi) / 1000.0
        q_cap_comp = 8.5 if cap_cmd else 0.0
        q_net_mvar = max(0.0, q_raw_mvar - q_cap_comp)
        state["REACTIVE_POWER_MVAR"] = int(round(q_net_mvar * 10))

        # 6. Transformer Winding Temperature dynamics
        ambient_c = 26.0
        load_factor = (total_amps / (self.feeder_1_base_amps + self.feeder_2_base_amps + 1e-6))
        target_temp = ambient_c + 35.0 * (load_factor ** 2)
        temp_delta = (target_temp - self.transformer_temp_c) * min(1.0, (dt / 120.0))
        t_noise = self.rng.gauss(0, 0.02) if self.noise_amplitude > 0 else 0.0
        self.transformer_temp_c += temp_delta + t_noise
        state["TRANSFORMER_TEMP_C"] = int(round(self.transformer_temp_c * 10))

        # 7. Buchholz gas relay: triggered by internal dielectric electrical faults, NOT temperature!
        earth_fault = int(state.get("EARTH_FAULT_ALARM", 0))
        # Buchholz triggers only on internal electrical arcing or earth fault
        state["TRANSFORMER_BUCHHOLZ_ALARM"] = 1 if earth_fault == 1 else 0

        return state

    def handle_write(self, tag_name: str, new_value: Any, current_state: Dict[str, Any]) -> Dict[str, Any]:
        """Update electrical substation state upon control actions."""
        state = dict(current_state)
        tag = self.identity.tags.get(tag_name)
        if not tag:
            return state

        if tag_name in ("FEEDER_1_CB_CMD", "FEEDER_2_CB_CMD", "BUS_COUPLER_CB_CMD",
                        "CAPACITOR_BANK_CMD", "AUTO_RECLOSE_ENABLE", "RELAY_PROTECTION_BYPASS"):
            val = 1 if int(new_value) != 0 else 0
            state[tag_name] = val

            if tag_name == "FEEDER_1_CB_CMD" and val == 0:
                state["FEEDER_1_CB_STATUS"] = 0
                state["FEEDER_1_CURRENT_A"] = 0
            elif tag_name == "FEEDER_2_CB_CMD" and val == 0:
                state["FEEDER_2_CB_STATUS"] = 0
                state["FEEDER_2_CURRENT_A"] = 0

        elif tag_name in ("OVERCURRENT_PICKUP_A", "UNDERFREQ_LOADSHED_STAGE1_HZ", "VOLTAGE_REGULATOR_TAP",
                          "REMOTE_TELEMETRY_KEY", "LOAD_REDUCTION_OVERRIDE"):
            state[tag_name] = int(new_value)

        return state
