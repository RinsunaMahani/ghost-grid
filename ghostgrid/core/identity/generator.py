"""Core identity generation module for GhostGrid.

Generates realistic, unique site identities, device banners, hardware metadata,
and dynamic register maps per installation. Ensures no static honeypot signatures
(like Conpot's default 'Mouser Factory') leak to attackers.
"""
from dataclasses import dataclass, field
from enum import Enum
import hashlib
import json
import os
import random
from typing import Dict, List, Optional, Any


class RegisterType(str, Enum):
    COIL = "coil"                          # 0xxxx (RW 1-bit)
    DISCRETE_INPUT = "discrete_input"      # 1xxxx (RO 1-bit)
    INPUT_REGISTER = "input_register"      # 3xxxx (RO 16-bit)
    HOLDING_REGISTER = "holding_register"  # 4xxxx (RW 16-bit)


@dataclass
class TagDefinition:
    name: str
    description: str
    reg_type: RegisterType
    address: int                           # Zero-based address offset for Modbus protocol
    data_type: str = "uint16"              # uint16, int16, bool
    scale_factor: float = 1.0              # e.g., 0.01 for frequency 50.00 Hz stored as 5000
    engineering_unit: str = ""
    is_honeytoken: bool = False            # Touching this generates immediate critical alarm
    read_only: bool = False
    default_value: Any = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "reg_type": self.reg_type.value,
            "address": self.address,
            "data_type": self.data_type,
            "scale_factor": self.scale_factor,
            "engineering_unit": self.engineering_unit,
            "is_honeytoken": self.is_honeytoken,
            "read_only": self.read_only,
            "default_value": self.default_value,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "TagDefinition":
        return cls(
            name=d["name"],
            description=d["description"],
            reg_type=RegisterType(d["reg_type"]),
            address=d["address"],
            data_type=d.get("data_type", "uint16"),
            scale_factor=d.get("scale_factor", 1.0),
            engineering_unit=d.get("engineering_unit", ""),
            is_honeytoken=d.get("is_honeytoken", False),
            read_only=d.get("read_only", False),
            default_value=d.get("default_value", 0),
        )


@dataclass
class SiteIdentity:
    site_name: str
    sector: str
    facility_type: str
    vendor: str
    model: str
    firmware_version: str
    serial_number: str
    mac_address: str
    unit_id: int
    tags: Dict[str, TagDefinition] = field(default_factory=dict)
    seed: Optional[str] = None
    location_code: str = "ZA-01"
    security_zone: str = "OT-PMR-L2"

    _address_map: Dict[tuple, TagDefinition] = field(default_factory=dict)

    def __post_init__(self):
        self._address_map = {
            (tag.reg_type, tag.address): tag for tag in self.tags.values()
        }

    def get_tag_by_address(self, reg_type: RegisterType, address: int) -> Optional[TagDefinition]:
        return self._address_map.get((reg_type, address))

    def get_device_info_objects(self) -> Dict[int, str]:
        """Returns standard Modbus MEI Read Device Identification objects (Modbus Spec v1.1b3)."""
        return {
            0x00: self.vendor,                                             # VendorName
            0x01: self.model,                                              # ProductCode
            0x02: self.firmware_version,                                  # MajorMinorRevision
            0x03: f"http://internal.{self.vendor.lower().replace(' ', '')}-scada.lan", # VendorUrl
            0x04: self.model,                                              # ProductName
            0x05: self.model.split()[0],                                   # ModelName
            0x06: self.site_name,                                          # UserApplicationName
            0x80: f"SN:{self.serial_number}",                             # SerialNumber (Optional)
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "site_name": self.site_name,
            "sector": self.sector,
            "facility_type": self.facility_type,
            "vendor": self.vendor,
            "model": self.model,
            "firmware_version": self.firmware_version,
            "serial_number": self.serial_number,
            "mac_address": self.mac_address,
            "unit_id": self.unit_id,
            "seed": self.seed,
            "location_code": self.location_code,
            "security_zone": self.security_zone,
            "tags": {k: v.to_dict() for k, v in self.tags.items()},
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "SiteIdentity":
        tags = {k: TagDefinition.from_dict(v) for k, v in d.get("tags", {}).items()}
        return cls(
            site_name=d["site_name"],
            sector=d["sector"],
            facility_type=d["facility_type"],
            vendor=d["vendor"],
            model=d["model"],
            firmware_version=d["firmware_version"],
            serial_number=d["serial_number"],
            mac_address=d["mac_address"],
            unit_id=d["unit_id"],
            tags=tags,
            seed=d.get("seed"),
            location_code=d.get("location_code", "ZA-01"),
            security_zone=d.get("security_zone", "OT-PMR-L2"),
        )


# Fully fictional, authentic-sounding South African facility templates
# Zero real entities, utilities, or real facility names
NEUTRAL_WATER_SITES = [
    ("District 4 Bulk Water Treatment Works", "water_treatment", "D04-BTW"),
    ("Central Highlands Pumping Station 2", "booster_station", "CHP-PS2"),
    ("Protea Ridge Distribution Reservoir", "distribution_reservoir", "PRD-RES"),
    ("Blydepoort Regional Booster Station", "booster_station", "BRP-BPS"),
    ("Olifants River Intake & Filtration Facility", "water_treatment", "ORF-WTP"),
    ("Kalahari Plains Water Supply Plant", "water_treatment", "KP-WSP"),
    ("Witwatersrand Municipal Reservoir 3", "distribution_reservoir", "WMR-RES3"),
    ("Drakensberg Foothills Purification Station", "water_treatment", "DFP-STA1"),
]

NEUTRAL_POWER_SITES = [
    ("Highveld Industrial 132/11kV Substation", "distribution_substation", "HVI-SUB-132"),
    ("Protea Distribution Substation 88kV", "distribution_substation", "PDS-SUB-088"),
    ("Southern Ridge Transmission Substation 275kV", "transmission_substation", "SRT-SUB-275"),
    ("Blue Crane Switching Substation 88kV", "switching_substation", "BCS-SWS-088"),
    ("Northern Plains Generation Intake 400kV", "converter_substation", "NPG-INT-400"),
    ("Acacia Park Municipal Distribution Substation", "distribution_substation", "APM-SUB-088"),
    ("Springbok Flats 132kV Incomer Station", "intake_substation", "SFI-SUB-132"),
    ("Veldview Regional Step-down Substation", "distribution_substation", "VRS-SUB-132"),
]

PLC_VENDORS = [
    ("Schneider Electric", "Modicon M580 ePAC", "v3.20-SA"),
    ("Schneider Electric", "Modicon M340 PLC", "v2.80-STD"),
    ("Siemens", "SIMATIC S7-1500 (CPU 1516-3 PN/DP)", "V2.9.2"),
    ("Siemens", "SIMATIC S7-1200 (CPU 1214C)", "V4.5.1"),
    ("Rockwell Automation", "Allen-Bradley ControlLogix 5580", "33.011"),
    ("Rockwell Automation", "Allen-Bradley CompactLogix 5380", "32.012"),
    ("ABB", "RTU560 Microprocessor Substation RTU", "12.4.1.0"),
]

VENDOR_OUIS = {
    "Schneider Electric": ["00:80:F4", "00:00:54", "00:60:64"],
    "Siemens": ["00:0E:8C", "00:1B:1B", "08:00:06"],
    "Rockwell Automation": ["00:00:BC", "00:80:F6", "00:1D:9C"],
    "ABB": ["00:20:4A", "AC:D3:64", "00:0C:4D"],
}


def _generate_mac(vendor: str, seed_str: str) -> str:
    """Generate a realistic OUI MAC address strictly matching the selected vendor."""
    h = hashlib.md5(seed_str.encode()).hexdigest()
    ouis = VENDOR_OUIS.get(vendor, ["00:80:F4", "00:00:54"])
    oui = ouis[int(h[:2], 16) % len(ouis)]
    suffix = f"{h[2:4]}:{h[4:6]}:{h[6:8]}"
    return f"{oui}:{suffix}".upper()


def _assign_randomized_addresses(tag_keys: List[str], base_range: range, rng: random.Random) -> Dict[str, int]:
    """Assign non-overlapping randomized addresses to tags within a register block."""
    count = len(tag_keys)
    step = max(1, len(base_range) // count)
    slots = list(base_range)[::step][:count]
    rng.shuffle(slots)
    return {k: slots[i] for i, k in enumerate(tag_keys)}


def _build_water_tags(rng: random.Random) -> Dict[str, TagDefinition]:
    """Generates water sector tags with randomized relative layouts, addresses, and initial baselines."""
    tags = {}

    # 1. Coils (Outputs RW) - addresses randomized between 0 and 25
    coil_keys = [
        "PUMP_1_CMD", "PUMP_2_CMD", "VALVE_INLET_CMD", "VALVE_DISCHARGE_CMD",
        "CHLORINE_DOSING_CMD", "EMERGENCY_SHUTDOWN_CMD"
    ]
    c_addrs = _assign_randomized_addresses(coil_keys, range(0, 15), rng)
    ht_coil_addr = rng.randint(18, 30)

    tags["PUMP_1_CMD"] = TagDefinition(
        name="PUMP_1_CMD", description="Main Intake Pump 1 Start/Stop Command",
        reg_type=RegisterType.COIL, address=c_addrs["PUMP_1_CMD"], default_value=1
    )
    tags["PUMP_2_CMD"] = TagDefinition(
        name="PUMP_2_CMD", description="Booster Pump 2 Start/Stop Command",
        reg_type=RegisterType.COIL, address=c_addrs["PUMP_2_CMD"], default_value=0
    )
    tags["VALVE_INLET_CMD"] = TagDefinition(
        name="VALVE_INLET_CMD", description="Inlet Isolation Motorized Valve Command",
        reg_type=RegisterType.COIL, address=c_addrs["VALVE_INLET_CMD"], default_value=1
    )
    tags["VALVE_DISCHARGE_CMD"] = TagDefinition(
        name="VALVE_DISCHARGE_CMD", description="Discharge Header Valve Command",
        reg_type=RegisterType.COIL, address=c_addrs["VALVE_DISCHARGE_CMD"], default_value=1
    )
    tags["CHLORINE_DOSING_CMD"] = TagDefinition(
        name="CHLORINE_DOSING_CMD", description="Chlorine Chemical Feed Dosing Pump",
        reg_type=RegisterType.COIL, address=c_addrs["CHLORINE_DOSING_CMD"], default_value=1
    )
    tags["EMERGENCY_SHUTDOWN_CMD"] = TagDefinition(
        name="EMERGENCY_SHUTDOWN_CMD", description="Emergency Plant Trip ESD",
        reg_type=RegisterType.COIL, address=c_addrs["EMERGENCY_SHUTDOWN_CMD"], default_value=0
    )
    tags["MAINTENANCE_OVERRIDE_LOCK"] = TagDefinition(
        name="MAINTENANCE_OVERRIDE_LOCK", description="Master Interlock Safety Bypass",
        reg_type=RegisterType.COIL, address=ht_coil_addr, default_value=0, is_honeytoken=True
    )

    # 2. Discrete Inputs (RO Digital) - addresses randomized between 0 and 20
    di_keys = [
        "PUMP_1_RUNNING", "PUMP_1_TRIP", "PUMP_2_RUNNING",
        "RESERVOIR_HIGH_SWITCH", "RESERVOIR_LOW_SWITCH", "LOCAL_REMOTE_KEY"
    ]
    di_addrs = _assign_randomized_addresses(di_keys, range(0, 16), rng)

    tags["PUMP_1_RUNNING"] = TagDefinition(
        name="PUMP_1_RUNNING", description="Intake Pump 1 Run Feedback Status",
        reg_type=RegisterType.DISCRETE_INPUT, address=di_addrs["PUMP_1_RUNNING"], default_value=1, read_only=True
    )
    tags["PUMP_1_TRIP"] = TagDefinition(
        name="PUMP_1_TRIP", description="Intake Pump 1 Thermal Overload Trip",
        reg_type=RegisterType.DISCRETE_INPUT, address=di_addrs["PUMP_1_TRIP"], default_value=0, read_only=True
    )
    tags["PUMP_2_RUNNING"] = TagDefinition(
        name="PUMP_2_RUNNING", description="Booster Pump 2 Run Feedback Status",
        reg_type=RegisterType.DISCRETE_INPUT, address=di_addrs["PUMP_2_RUNNING"], default_value=0, read_only=True
    )
    tags["RESERVOIR_HIGH_SWITCH"] = TagDefinition(
        name="RESERVOIR_HIGH_SWITCH", description="Reservoir Level High-High Level Float Switch",
        reg_type=RegisterType.DISCRETE_INPUT, address=di_addrs["RESERVOIR_HIGH_SWITCH"], default_value=0, read_only=True
    )
    tags["RESERVOIR_LOW_SWITCH"] = TagDefinition(
        name="RESERVOIR_LOW_SWITCH", description="Reservoir Low-Low Dry Run Protection Switch",
        reg_type=RegisterType.DISCRETE_INPUT, address=di_addrs["RESERVOIR_LOW_SWITCH"], default_value=0, read_only=True
    )
    tags["LOCAL_REMOTE_KEY"] = TagDefinition(
        name="LOCAL_REMOTE_KEY", description="Station SCADA Control Mode (0=Local, 1=Remote)",
        reg_type=RegisterType.DISCRETE_INPUT, address=di_addrs["LOCAL_REMOTE_KEY"], default_value=1, read_only=True
    )

    # 3. Input Registers (RO Analog) - addresses randomized between 0 and 25
    ir_keys = [
        "RESERVOIR_LEVEL_PCT", "INFLOW_RATE_M3H", "OUTFLOW_RATE_M3H",
        "DISCHARGE_PRESSURE_BAR", "SUCTION_PRESSURE_BAR", "CHLORINE_RESIDUAL_PPM",
        "TURBIDITY_NTU", "WATER_PH"
    ]
    ir_addrs = _assign_randomized_addresses(ir_keys, range(0, 24), rng)

    # Randomized initial baseline values within realistic bounds
    init_level = rng.randint(680, 820)       # 68.0% - 82.0%
    init_inflow = rng.randint(1780, 1860)    # 1780 - 1860 m3/h
    init_outflow = rng.randint(1720, 1780)   # 1720 - 1780 m3/h
    init_press = rng.randint(600, 640)       # 6.00 - 6.40 bar
    init_suct = rng.randint(135, 155)        # 1.35 - 1.55 bar
    init_cl = rng.randint(115, 135)          # 1.15 - 1.35 ppm
    init_turb = rng.randint(35, 50)          # 0.35 - 0.50 NTU
    init_ph = rng.randint(745, 775)          # 7.45 - 7.75 pH

    tags["RESERVOIR_LEVEL_PCT"] = TagDefinition(
        name="RESERVOIR_LEVEL_PCT", description="Bulk Reservoir Storage Level",
        reg_type=RegisterType.INPUT_REGISTER, address=ir_addrs["RESERVOIR_LEVEL_PCT"], scale_factor=0.1,
        engineering_unit="%", default_value=init_level, read_only=True
    )
    tags["INFLOW_RATE_M3H"] = TagDefinition(
        name="INFLOW_RATE_M3H", description="Raw Water Inlet Flow Meter (FT-101)",
        reg_type=RegisterType.INPUT_REGISTER, address=ir_addrs["INFLOW_RATE_M3H"], scale_factor=1.0,
        engineering_unit="m3/h", default_value=init_inflow, read_only=True
    )
    tags["OUTFLOW_RATE_M3H"] = TagDefinition(
        name="OUTFLOW_RATE_M3H", description="Treated Bulk Outflow Flow Meter (FT-102)",
        reg_type=RegisterType.INPUT_REGISTER, address=ir_addrs["OUTFLOW_RATE_M3H"], scale_factor=1.0,
        engineering_unit="m3/h", default_value=init_outflow, read_only=True
    )
    tags["DISCHARGE_PRESSURE_BAR"] = TagDefinition(
        name="DISCHARGE_PRESSURE_BAR", description="Main Delivery Header Pressure (PT-103)",
        reg_type=RegisterType.INPUT_REGISTER, address=ir_addrs["DISCHARGE_PRESSURE_BAR"], scale_factor=0.01,
        engineering_unit="bar", default_value=init_press, read_only=True
    )
    tags["SUCTION_PRESSURE_BAR"] = TagDefinition(
        name="SUCTION_PRESSURE_BAR", description="Pump Suction Manifold Pressure (PT-101)",
        reg_type=RegisterType.INPUT_REGISTER, address=ir_addrs["SUCTION_PRESSURE_BAR"], scale_factor=0.01,
        engineering_unit="bar", default_value=init_suct, read_only=True
    )
    tags["CHLORINE_RESIDUAL_PPM"] = TagDefinition(
        name="CHLORINE_RESIDUAL_PPM", description="Free Chlorine Residual (Target: 0.2-2.0 mg/L)",
        reg_type=RegisterType.INPUT_REGISTER, address=ir_addrs["CHLORINE_RESIDUAL_PPM"], scale_factor=0.01,
        engineering_unit="mg/L", default_value=init_cl, read_only=True
    )
    tags["TURBIDITY_NTU"] = TagDefinition(
        name="TURBIDITY_NTU", description="Water Turbidity (Operational Limit: < 1.0 NTU)",
        reg_type=RegisterType.INPUT_REGISTER, address=ir_addrs["TURBIDITY_NTU"], scale_factor=0.01,
        engineering_unit="NTU", default_value=init_turb, read_only=True
    )
    tags["WATER_PH"] = TagDefinition(
        name="WATER_PH", description="Water pH Analyzer (Target: 7.0 - 8.5)",
        reg_type=RegisterType.INPUT_REGISTER, address=ir_addrs["WATER_PH"], scale_factor=0.01,
        engineering_unit="pH", default_value=init_ph, read_only=True
    )

    # 4. Holding Registers (RW Parameters & Setpoints)
    hr_keys = [
        "LEVEL_SETPOINT_PCT", "PRESSURE_SETPOINT_BAR", "DOSING_RATE_L_HR",
        "HIGH_LEVEL_ALARM_LIMIT", "LOW_LEVEL_ALARM_LIMIT"
    ]
    hr_addrs = _assign_randomized_addresses(hr_keys, range(0, 20), rng)

    init_sp_lvl = rng.randint(780, 840)      # 78.0% - 84.0%
    init_sp_press = rng.randint(620, 680)    # 6.20 - 6.80 bar
    init_sp_dosing = rng.randint(40, 50)     # 4.0 - 5.0 L/h
    init_hi_lim = rng.randint(910, 940)      # 91.0% - 94.0%
    init_lo_lim = rng.randint(200, 260)      # 20.0% - 26.0%

    tags["LEVEL_SETPOINT_PCT"] = TagDefinition(
        name="LEVEL_SETPOINT_PCT", description="Target Reservoir Holding Level Setpoint",
        reg_type=RegisterType.HOLDING_REGISTER, address=hr_addrs["LEVEL_SETPOINT_PCT"], scale_factor=0.1,
        engineering_unit="%", default_value=init_sp_lvl
    )
    tags["PRESSURE_SETPOINT_BAR"] = TagDefinition(
        name="PRESSURE_SETPOINT_BAR", description="Header Pressure Regulator Setpoint",
        reg_type=RegisterType.HOLDING_REGISTER, address=hr_addrs["PRESSURE_SETPOINT_BAR"], scale_factor=0.01,
        engineering_unit="bar", default_value=init_sp_press
    )
    tags["DOSING_RATE_L_HR"] = TagDefinition(
        name="DOSING_RATE_L_HR", description="Hypochlorite Dosing Injection Rate",
        reg_type=RegisterType.HOLDING_REGISTER, address=hr_addrs["DOSING_RATE_L_HR"], scale_factor=0.1,
        engineering_unit="L/h", default_value=init_sp_dosing
    )
    tags["HIGH_LEVEL_ALARM_LIMIT"] = TagDefinition(
        name="HIGH_LEVEL_ALARM_LIMIT", description="High-High Alarm Trip Threshold",
        reg_type=RegisterType.HOLDING_REGISTER, address=hr_addrs["HIGH_LEVEL_ALARM_LIMIT"], scale_factor=0.1,
        engineering_unit="%", default_value=init_hi_lim
    )
    tags["LOW_LEVEL_ALARM_LIMIT"] = TagDefinition(
        name="LOW_LEVEL_ALARM_LIMIT", description="Low-Low Alarm Trip Threshold",
        reg_type=RegisterType.HOLDING_REGISTER, address=hr_addrs["LOW_LEVEL_ALARM_LIMIT"], scale_factor=0.1,
        engineering_unit="%", default_value=init_lo_lim
    )

    # Honeytokens in Holding Registers
    ht1_addr = rng.randint(75, 120)
    ht1_val = rng.randint(0x1000, 0xFEFE)
    tags["BACKDOOR_CALIBRATION_KEY"] = TagDefinition(
        name="BACKDOOR_CALIBRATION_KEY", description="OEM Vendor Factory Calibration Password Register",
        reg_type=RegisterType.HOLDING_REGISTER, address=ht1_addr, scale_factor=1.0,
        engineering_unit="", default_value=ht1_val, is_honeytoken=True
    )
    tags["SAFETY_INTERLOCK_DISABLE"] = TagDefinition(
        name="SAFETY_INTERLOCK_DISABLE", description="Emergency SANS 241 Compliance Safety Disable Flag",
        reg_type=RegisterType.HOLDING_REGISTER, address=ht1_addr + 1, scale_factor=1.0,
        engineering_unit="", default_value=0, is_honeytoken=True
    )

    return tags


def _build_power_tags(rng: random.Random) -> Dict[str, TagDefinition]:
    """Generates power sector tags with randomized relative layouts, addresses, and initial baselines."""
    tags = {}

    # 1. Coils (Outputs RW)
    coil_keys = [
        "FEEDER_1_CB_CMD", "FEEDER_2_CB_CMD", "BUS_COUPLER_CB_CMD",
        "CAPACITOR_BANK_CMD", "AUTO_RECLOSE_ENABLE"
    ]
    c_addrs = _assign_randomized_addresses(coil_keys, range(0, 15), rng)
    ht_coil_addr = rng.randint(18, 30)

    tags["FEEDER_1_CB_CMD"] = TagDefinition(
        name="FEEDER_1_CB_CMD", description="Feeder 1 Circuit Breaker Trip/Close Command (1=Close, 0=Trip)",
        reg_type=RegisterType.COIL, address=c_addrs["FEEDER_1_CB_CMD"], default_value=1
    )
    tags["FEEDER_2_CB_CMD"] = TagDefinition(
        name="FEEDER_2_CB_CMD", description="Feeder 2 Circuit Breaker Trip/Close Command (1=Close, 0=Trip)",
        reg_type=RegisterType.COIL, address=c_addrs["FEEDER_2_CB_CMD"], default_value=1
    )
    tags["BUS_COUPLER_CB_CMD"] = TagDefinition(
        name="BUS_COUPLER_CB_CMD", description="88kV Bus Coupler Breaker Command",
        reg_type=RegisterType.COIL, address=c_addrs["BUS_COUPLER_CB_CMD"], default_value=0
    )
    tags["CAPACITOR_BANK_CMD"] = TagDefinition(
        name="CAPACITOR_BANK_CMD", description="VAr Compensation Capacitor Bank Step 1",
        reg_type=RegisterType.COIL, address=c_addrs["CAPACITOR_BANK_CMD"], default_value=1
    )
    tags["AUTO_RECLOSE_ENABLE"] = TagDefinition(
        name="AUTO_RECLOSE_ENABLE", description="Line Auto-Reclosing System Enable",
        reg_type=RegisterType.COIL, address=c_addrs["AUTO_RECLOSE_ENABLE"], default_value=1
    )
    tags["RELAY_PROTECTION_BYPASS"] = TagDefinition(
        name="RELAY_PROTECTION_BYPASS", description="Distance & Overcurrent Protection Interlock Bypass",
        reg_type=RegisterType.COIL, address=ht_coil_addr, default_value=0, is_honeytoken=True
    )

    # 2. Discrete Inputs (RO Digital)
    di_keys = [
        "FEEDER_1_CB_STATUS", "FEEDER_2_CB_STATUS", "TRANSFORMER_BUCHHOLZ_ALARM",
        "EARTH_FAULT_ALARM", "GRID_SYNC_CHECK"
    ]
    di_addrs = _assign_randomized_addresses(di_keys, range(0, 15), rng)

    tags["FEEDER_1_CB_STATUS"] = TagDefinition(
        name="FEEDER_1_CB_STATUS", description="Feeder 1 Breaker Auxiliary Contact (1=Closed, 0=Open)",
        reg_type=RegisterType.DISCRETE_INPUT, address=di_addrs["FEEDER_1_CB_STATUS"], default_value=1, read_only=True
    )
    tags["FEEDER_2_CB_STATUS"] = TagDefinition(
        name="FEEDER_2_CB_STATUS", description="Feeder 2 Breaker Auxiliary Contact (1=Closed, 0=Open)",
        reg_type=RegisterType.DISCRETE_INPUT, address=di_addrs["FEEDER_2_CB_STATUS"], default_value=1, read_only=True
    )
    tags["TRANSFORMER_BUCHHOLZ_ALARM"] = TagDefinition(
        name="TRANSFORMER_BUCHHOLZ_ALARM", description="Main Step-down Tx Gas Buchholz Relay Alert",
        reg_type=RegisterType.DISCRETE_INPUT, address=di_addrs["TRANSFORMER_BUCHHOLZ_ALARM"], default_value=0, read_only=True
    )
    tags["EARTH_FAULT_ALARM"] = TagDefinition(
        name="EARTH_FAULT_ALARM", description="Earth Leakage / Neutral Displacement Indicator",
        reg_type=RegisterType.DISCRETE_INPUT, address=di_addrs["EARTH_FAULT_ALARM"], default_value=0, read_only=True
    )
    tags["GRID_SYNC_CHECK"] = TagDefinition(
        name="GRID_SYNC_CHECK", description="Synchro-check Relay Synchronism Acceptable",
        reg_type=RegisterType.DISCRETE_INPUT, address=di_addrs["GRID_SYNC_CHECK"], default_value=1, read_only=True
    )

    # 3. Input Registers (RO Analog)
    ir_keys = [
        "GRID_FREQUENCY_HZ", "BUS_VOLTAGE_KV", "FEEDER_1_CURRENT_A",
        "FEEDER_2_CURRENT_A", "ACTIVE_POWER_MW", "REACTIVE_POWER_MVAR",
        "TRANSFORMER_TEMP_C"
    ]
    ir_addrs = _assign_randomized_addresses(ir_keys, range(0, 20), rng)

    init_freq = rng.randint(4996, 5004)      # 49.96 - 50.04 Hz
    init_bus_kv = rng.randint(878, 886)      # 87.8 - 88.6 kV
    # Baseline feeder currents calibrated so active power P = sqrt(3)*V*I*pf matches ~46 MW
    init_f1_i = rng.randint(168, 180)        # ~175 A
    init_f2_i = rng.randint(150, 162)        # ~155 A
    init_tot_i = init_f1_i + init_f2_i
    # P = sqrt(3) * (init_bus_kv/10.0) * init_tot_i * 0.92 / 1000
    calc_p_mw = (1.73205 * (init_bus_kv / 10.0) * init_tot_i * 0.92) / 1000.0
    init_p_mw = int(round(calc_p_mw * 10))
    init_q_mvar = rng.randint(110, 135)
    init_temp = rng.randint(560, 605)        # 56.0 - 60.5 °C

    tags["GRID_FREQUENCY_HZ"] = TagDefinition(
        name="GRID_FREQUENCY_HZ", description="National Grid System Frequency (SA Grid Code Nominal: 50.00 Hz)",
        reg_type=RegisterType.INPUT_REGISTER, address=ir_addrs["GRID_FREQUENCY_HZ"], scale_factor=0.01,
        engineering_unit="Hz", default_value=init_freq, read_only=True
    )
    tags["BUS_VOLTAGE_KV"] = TagDefinition(
        name="BUS_VOLTAGE_KV", description="Main Incomer Bus A Voltage (Nominal 88.0 kV)",
        reg_type=RegisterType.INPUT_REGISTER, address=ir_addrs["BUS_VOLTAGE_KV"], scale_factor=0.1,
        engineering_unit="kV", default_value=init_bus_kv, read_only=True
    )
    tags["FEEDER_1_CURRENT_A"] = TagDefinition(
        name="FEEDER_1_CURRENT_A", description="Feeder 1 True RMS Phase Current",
        reg_type=RegisterType.INPUT_REGISTER, address=ir_addrs["FEEDER_1_CURRENT_A"], scale_factor=1.0,
        engineering_unit="A", default_value=init_f1_i, read_only=True
    )
    tags["FEEDER_2_CURRENT_A"] = TagDefinition(
        name="FEEDER_2_CURRENT_A", description="Feeder 2 True RMS Phase Current",
        reg_type=RegisterType.INPUT_REGISTER, address=ir_addrs["FEEDER_2_CURRENT_A"], scale_factor=1.0,
        engineering_unit="A", default_value=init_f2_i, read_only=True
    )
    tags["ACTIVE_POWER_MW"] = TagDefinition(
        name="ACTIVE_POWER_MW", description="Total Substation Active Power P",
        reg_type=RegisterType.INPUT_REGISTER, address=ir_addrs["ACTIVE_POWER_MW"], scale_factor=0.1,
        engineering_unit="MW", default_value=init_p_mw, read_only=True
    )
    tags["REACTIVE_POWER_MVAR"] = TagDefinition(
        name="REACTIVE_POWER_MVAR", description="Total Substation Reactive Power Q",
        reg_type=RegisterType.INPUT_REGISTER, address=ir_addrs["REACTIVE_POWER_MVAR"], scale_factor=0.1,
        engineering_unit="MVAr", default_value=init_q_mvar, read_only=True
    )
    tags["TRANSFORMER_TEMP_C"] = TagDefinition(
        name="TRANSFORMER_TEMP_C", description="Winding Temperature Indicator (WTI)",
        reg_type=RegisterType.INPUT_REGISTER, address=ir_addrs["TRANSFORMER_TEMP_C"], scale_factor=0.1,
        engineering_unit="°C", default_value=init_temp, read_only=True
    )

    # 4. Holding Registers (RW Parameters & Setpoints)
    hr_keys = [
        "OVERCURRENT_PICKUP_A", "UNDERFREQ_LOADSHED_STAGE1_HZ", "VOLTAGE_REGULATOR_TAP"
    ]
    hr_addrs = _assign_randomized_addresses(hr_keys, range(0, 15), rng)

    tags["OVERCURRENT_PICKUP_A"] = TagDefinition(
        name="OVERCURRENT_PICKUP_A", description="Feeder Protection Overcurrent 51 Trip Setting",
        reg_type=RegisterType.HOLDING_REGISTER, address=hr_addrs["OVERCURRENT_PICKUP_A"], scale_factor=1.0,
        engineering_unit="A", default_value=rng.randint(420, 480)
    )
    tags["UNDERFREQ_LOADSHED_STAGE1_HZ"] = TagDefinition(
        name="UNDERFREQ_LOADSHED_STAGE1_HZ", description="UFLS Stage 1 Underfrequency Trip Threshold",
        reg_type=RegisterType.HOLDING_REGISTER, address=hr_addrs["UNDERFREQ_LOADSHED_STAGE1_HZ"], scale_factor=0.01,
        engineering_unit="Hz", default_value=rng.randint(4915, 4925)
    )
    tags["VOLTAGE_REGULATOR_TAP"] = TagDefinition(
        name="VOLTAGE_REGULATOR_TAP", description="On-Load Tap Changer (OLTC) Position (1-16)",
        reg_type=RegisterType.HOLDING_REGISTER, address=hr_addrs["VOLTAGE_REGULATOR_TAP"], scale_factor=1.0,
        engineering_unit="Tap", default_value=8
    )

    ht1_addr = rng.randint(75, 120)
    ht1_val = rng.randint(0x1000, 0xFEFE)
    tags["REMOTE_TELEMETRY_KEY"] = TagDefinition(
        name="REMOTE_TELEMETRY_KEY", description="National Control Centre Telemetry Encryption Key",
        reg_type=RegisterType.HOLDING_REGISTER, address=ht1_addr, scale_factor=1.0,
        engineering_unit="", default_value=ht1_val, is_honeytoken=True
    )
    tags["LOAD_REDUCTION_OVERRIDE"] = TagDefinition(
        name="LOAD_REDUCTION_OVERRIDE", description="Municipal Emergency Load Reduction Inhibit Register",
        reg_type=RegisterType.HOLDING_REGISTER, address=ht1_addr + 1, scale_factor=1.0,
        engineering_unit="", default_value=0, is_honeytoken=True
    )

    return tags


def generate_site_identity(
    sector: str = "water",
    site_name: Optional[str] = None,
    vendor: Optional[str] = None,
    model: Optional[str] = None,
    firmware_version: Optional[str] = None,
    serial_number: Optional[str] = None,
    unit_id: int = 1,
    seed: Optional[str] = None,
    location_code: Optional[str] = None,
    security_zone: str = "OT-PMR-L2",
) -> SiteIdentity:
    """Generate a unique, believable SiteIdentity with dynamic register mappings and vendor-matched MAC."""
    actual_seed = seed if seed else f"{sector}_{random.randint(10000000, 99999999)}"
    rng = random.Random(actual_seed)

    sec = sector.lower()
    if sec not in ("water", "power"):
        sec = "water"

    loc_c = location_code
    if not site_name:
        candidates = NEUTRAL_WATER_SITES if sec == "water" else NEUTRAL_POWER_SITES
        name, fac_type, auto_loc = rng.choice(candidates)
        if not loc_c:
            loc_c = auto_loc
    else:
        name = site_name
        fac_type = "water_treatment" if sec == "water" else "distribution_substation"
        if not loc_c:
            loc_c = f"ZA-{sec.upper()[:3]}-01"

    if not vendor or not model:
        v_choice, m_choice, f_choice = rng.choice(PLC_VENDORS)
        v = vendor or v_choice
        m = model or m_choice
        f = firmware_version or f_choice
    else:
        v = vendor
        m = model
        f = firmware_version or "v3.10-SA"

    if not serial_number:
        sn = f"ZA-{sec.upper()[:3]}-{rng.randint(100000, 999999)}"
    else:
        sn = serial_number

    mac = _generate_mac(v, f"{actual_seed}:{name}:{v}:{m}:{sn}")

    # Build dynamically mapped tags with unique relative offsets
    if sec == "water":
        tags = _build_water_tags(rng=rng)
    else:
        tags = _build_power_tags(rng=rng)

    return SiteIdentity(
        site_name=name,
        sector=sec,
        facility_type=fac_type,
        vendor=v,
        model=m,
        firmware_version=f,
        serial_number=sn,
        mac_address=mac,
        unit_id=unit_id,
        tags=tags,
        seed=actual_seed,
        location_code=loc_c,
        security_zone=security_zone,
    )


def save_identity(identity: SiteIdentity, path: str = "ghostgrid_identity.json") -> None:
    """Persist identity to JSON so decoy keeps the exact same persona across restarts."""
    data = identity.to_dict()
    tmp_path = path + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp_path, path)


def load_identity(path: str = "ghostgrid_identity.json") -> Optional[SiteIdentity]:
    """Load persisted site identity if present."""
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return SiteIdentity.from_dict(data)
    except Exception as e:
        print(f"[GhostGrid Identity] Warning: Failed to load identity from {path}: {e}")
        return None
