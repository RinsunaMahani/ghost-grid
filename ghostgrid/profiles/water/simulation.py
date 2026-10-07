"""Water sector physics simulation for GhostGrid.

Models bulk water treatment and pumping station hydraulic dynamics:
- Decimal float precision: avoids truncation error so reservoir doesn't drain
- Closed-loop level setpoint control: Pump 1 cycles/throttles at LEVEL_SETPOINT_PCT
- Auxiliary Pump 2: booster pump adds +1,100 m3/h when commanded
- Setpoint-driven dynamics: pressure regulator & SANS 241 dosing track setpoints
- Dry-run protection switch aligns with LOW_LEVEL_ALARM_LIMIT register
"""
import random
from typing import Dict, Any
from ghostgrid.profiles.base import SectorProfile
from ghostgrid.core.identity import SiteIdentity


class WaterProfile(SectorProfile):
    """Bulk water treatment & pump station physics simulator with closed-loop setpoints."""

    def __init__(self, identity: SiteIdentity, noise_amplitude: float = 0.015):
        super().__init__(identity, noise_amplitude)
        self.rng = random.Random()
        # Physical plant parameters
        self.reservoir_capacity_m3 = 50000.0  # 50 ML bulk storage reservoir
        self.nominal_inflow_m3h = 1820.0     # Pumping rate for Pump 1
        self.nominal_p2_inflow_m3h = 1100.0  # Booster rate for Pump 2
        self.nominal_outflow_m3h = 1750.0    # Gravity delivery to municipal feeders

        # Internal continuous physical state (floating point decimals)
        self.level_pct: float = 74.5
        self.chlorine_ppm: float = 1.25
        self.turbidity_ntu: float = 0.42
        self.water_ph: float = 7.60
        self.discharge_bar: float = 6.20
        self.suction_bar: float = 1.45

        # Pump 1 supervisory cycling state
        self._p1_throttled: bool = False

        # Initialize from tag defaults if present
        lvl_tag = self.identity.tags.get("RESERVOIR_LEVEL_PCT")
        if lvl_tag and lvl_tag.default_value:
            self.level_pct = float(lvl_tag.default_value) * lvl_tag.scale_factor
        cl_tag = self.identity.tags.get("CHLORINE_RESIDUAL_PPM")
        if cl_tag and cl_tag.default_value:
            self.chlorine_ppm = float(cl_tag.default_value) * cl_tag.scale_factor
        p_tag = self.identity.tags.get("DISCHARGE_PRESSURE_BAR")
        if p_tag and p_tag.default_value:
            self.discharge_bar = float(p_tag.default_value) * p_tag.scale_factor

    @property
    def sector_name(self) -> str:
        return "water"

    def initialize_state(self) -> Dict[str, Any]:
        """Initialize plant telemetry from tag default values."""
        state = {}
        for tag_name, tag in self.identity.tags.items():
            state[tag_name] = tag.default_value
        return state

    def step(self, dt: float, current_state: Dict[str, Any]) -> Dict[str, Any]:
        """Integrate 1 step of water hydraulic physics with active setpoint control."""
        state = dict(current_state)

        # 1. Read operator / attacker commands
        esd_tripped = bool(state.get("EMERGENCY_SHUTDOWN_CMD", 0))
        p1_cmd = bool(state.get("PUMP_1_CMD", 1)) and not esd_tripped
        p2_cmd = bool(state.get("PUMP_2_CMD", 0)) and not esd_tripped
        inlet_valve_open = bool(state.get("VALVE_INLET_CMD", 1)) and not esd_tripped
        discharge_valve_open = bool(state.get("VALVE_DISCHARGE_CMD", 1)) and not esd_tripped
        chlorine_cmd = bool(state.get("CHLORINE_DOSING_CMD", 1)) and not esd_tripped

        # 2. Read live setpoints from holding registers
        sp_level_pct = float(state.get("LEVEL_SETPOINT_PCT", 800)) * 0.1       # e.g., 80.0%
        sp_press_bar = float(state.get("PRESSURE_SETPOINT_BAR", 650)) * 0.01    # e.g., 6.50 bar
        sp_dosing_lhr = float(state.get("DOSING_RATE_L_HR", 45)) * 0.1          # e.g., 4.5 L/h
        low_limit_pct = float(state.get("LOW_LEVEL_ALARM_LIMIT", 250)) * 0.1   # e.g., 25.0%
        high_limit_pct = float(state.get("HIGH_LEVEL_ALARM_LIMIT", 920)) * 0.1 # e.g., 92.0%

        # 3. Limit Switches matching holding register alarm limits
        low_switch = 1 if self.level_pct <= low_limit_pct else 0
        high_switch = 1 if self.level_pct >= high_limit_pct else 0
        state["RESERVOIR_LOW_SWITCH"] = low_switch
        state["RESERVOIR_HIGH_SWITCH"] = high_switch

        # Dry run protection interlock: trip pumps when reservoir drops to low limit
        pumps_tripped = esd_tripped or (low_switch == 1)
        state["PUMP_1_TRIP"] = 1 if pumps_tripped else 0

        # 4. Closed-loop level setpoint supervisory control (hysteresis cycle)
        if self.level_pct >= sp_level_pct:
            self._p1_throttled = True
        elif self.level_pct <= (sp_level_pct - 1.5):
            self._p1_throttled = False

        p1_running = 1 if (p1_cmd and not pumps_tripped and not self._p1_throttled) else 0
        p2_running = 1 if (p2_cmd and not pumps_tripped) else 0

        state["PUMP_1_RUNNING"] = p1_running
        state["PUMP_2_RUNNING"] = p2_running

        # 5. Hydraulic Flows (Pump 1 + Booster Pump 2)
        noise_p1 = self.rng.gauss(0, self.noise_amplitude) if self.noise_amplitude > 0 else 0.0
        noise_p2 = self.rng.gauss(0, self.noise_amplitude) if self.noise_amplitude > 0 else 0.0
        p1_flow = (self.nominal_inflow_m3h * (1.0 + noise_p1)) if (p1_running and inlet_valve_open) else 0.0
        p2_flow = (self.nominal_p2_inflow_m3h * (1.0 + noise_p2)) if (p2_running and inlet_valve_open) else 0.0
        raw_inflow = p1_flow + p2_flow

        if discharge_valve_open and self.level_pct > 0.0:
            outflow_noise = self.rng.gauss(0, self.noise_amplitude) if self.noise_amplitude > 0 else 0.0
            raw_outflow = self.nominal_outflow_m3h * (1.0 + outflow_noise)
        else:
            raw_outflow = 0.0

        # 6. Reservoir mass balance using floating-point decimals
        delta_volume = (raw_inflow - raw_outflow) * (dt / 3600.0)
        curr_volume = (self.level_pct / 100.0) * self.reservoir_capacity_m3
        new_volume = max(0.0, min(self.reservoir_capacity_m3, curr_volume + delta_volume))
        self.level_pct = (new_volume / self.reservoir_capacity_m3) * 100.0

        # 7. Discharge & Suction Pressures driven by setpoint and active pumps
        if (p1_running or p2_running) and discharge_valve_open:
            # Active header pressure regulator drives pressure toward setpoint
            boost = 0.40 if (p1_running and p2_running) else 0.0
            target_p = sp_press_bar + boost + (self.level_pct - 50.0) * 0.005
            p_noise = self.rng.gauss(0, self.noise_amplitude * 1.5) if self.noise_amplitude > 0 else 0.0
            self.discharge_bar += (target_p - self.discharge_bar) * min(1.0, dt * 0.1) + p_noise
            s_noise = self.rng.gauss(0, self.noise_amplitude) if self.noise_amplitude > 0 else 0.0
            self.suction_bar = max(0.5, 1.45 + s_noise)
        else:
            # Static elevation head when pumps stopped
            self.discharge_bar = 2.10 + (self.rng.gauss(0, 0.02) if self.noise_amplitude > 0 else 0.0)
            self.suction_bar = 0.80 + (self.rng.gauss(0, 0.01) if self.noise_amplitude > 0 else 0.0)

        # 8. SANS 241 Water Quality driven by DOSING_RATE_L_HR setpoint
        if chlorine_cmd and raw_inflow > 0 and sp_dosing_lhr > 0:
            target_cl = (sp_dosing_lhr / 4.5) * 1.25 + (self.rng.gauss(0, 0.02) if self.noise_amplitude > 0 else 0.0)
            self.chlorine_ppm += (target_cl - self.chlorine_ppm) * min(1.0, dt * 0.05)
        else:
            # Chlorine decay over time
            self.chlorine_ppm = max(0.05, self.chlorine_ppm - (0.01 * (dt / 60.0)))

        base_turbidity = 0.42 if raw_inflow > 0 else 0.28
        turb_noise = self.rng.gauss(0, 0.02) if self.noise_amplitude > 0 else 0.0
        self.turbidity_ntu = max(0.10, base_turbidity + turb_noise)

        ph_noise = self.rng.gauss(0, 0.01) if self.noise_amplitude > 0 else 0.0
        self.water_ph = 7.60 + ph_noise

        # 9. Update state dict with integer register representations
        state["INFLOW_RATE_M3H"] = int(round(raw_inflow))
        state["OUTFLOW_RATE_M3H"] = int(round(raw_outflow))
        state["RESERVOIR_LEVEL_PCT"] = int(round(self.level_pct * 10))
        state["DISCHARGE_PRESSURE_BAR"] = int(round(self.discharge_bar * 100))
        state["SUCTION_PRESSURE_BAR"] = int(round(self.suction_bar * 100))
        state["CHLORINE_RESIDUAL_PPM"] = int(round(self.chlorine_ppm * 100))
        state["TURBIDITY_NTU"] = int(round(self.turbidity_ntu * 100))
        state["WATER_PH"] = int(round(self.water_ph * 100))

        return state

    def handle_write(self, tag_name: str, new_value: Any, current_state: Dict[str, Any]) -> Dict[str, Any]:
        """Update plant state based on operator or attacker commands."""
        state = dict(current_state)
        tag = self.identity.tags.get(tag_name)
        if not tag:
            return state

        # Coils
        if tag_name in ("PUMP_1_CMD", "PUMP_2_CMD", "VALVE_INLET_CMD", "VALVE_DISCHARGE_CMD",
                        "CHLORINE_DOSING_CMD", "EMERGENCY_SHUTDOWN_CMD", "MAINTENANCE_OVERRIDE_LOCK"):
            val = 1 if int(new_value) != 0 else 0
            state[tag_name] = val

            if tag_name == "EMERGENCY_SHUTDOWN_CMD" and val == 1:
                state["PUMP_1_CMD"] = 0
                state["PUMP_2_CMD"] = 0
                state["VALVE_INLET_CMD"] = 0
                state["PUMP_1_RUNNING"] = 0
                state["PUMP_2_RUNNING"] = 0
                state["PUMP_1_TRIP"] = 1
                state["INFLOW_RATE_M3H"] = 0
                self.discharge_bar = 2.10

            elif tag_name == "PUMP_1_CMD" and val == 0:
                state["PUMP_1_RUNNING"] = 0

            elif tag_name == "PUMP_2_CMD" and val == 0:
                state["PUMP_2_RUNNING"] = 0

            elif tag_name == "VALVE_INLET_CMD" and val == 0:
                state["INFLOW_RATE_M3H"] = 0

            elif tag_name == "VALVE_DISCHARGE_CMD" and val == 0:
                state["OUTFLOW_RATE_M3H"] = 0

        # Holding register setpoints
        elif tag_name in ("LEVEL_SETPOINT_PCT", "PRESSURE_SETPOINT_BAR", "DOSING_RATE_L_HR",
                          "HIGH_LEVEL_ALARM_LIMIT", "LOW_LEVEL_ALARM_LIMIT",
                          "BACKDOOR_CALIBRATION_KEY", "SAFETY_INTERLOCK_DISABLE"):
            state[tag_name] = int(new_value)

        return state
