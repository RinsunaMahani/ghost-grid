"""What the scenario director is allowed to change.

Only operational setpoints, each inside a plausible operating range for this plant model.
Everything else is off limits, including commands, trips, alarm limits and protection settings.
That matters because settings can cause trips indirectly: on this plant a raised low-level alarm
limit trips the pumps (dry-run protection) and a lowered overcurrent pickup trips a feeder. A
storyline must never be able to cause a trip, directly or through a setting.

Kept in its own module so the LLM client can tell the model the same ranges the director enforces.
"""
from typing import Dict, Optional, Tuple

# Raw register values, as the Modbus map stores them.
ADJUSTABLE_SETPOINTS: Dict[str, Dict[str, Tuple[int, int]]] = {
    "water": {
        "LEVEL_SETPOINT_PCT": (700, 880),       # 70.0-88.0 %: clear of the ~91 % high-level alarm
        "PRESSURE_SETPOINT_BAR": (550, 720),    # 5.50-7.20 bar
        "DOSING_RATE_L_HR": (30, 65),           # 3.0-6.5 L/h
    },
    "power": {
        "VOLTAGE_REGULATOR_TAP": (6, 10),       # nominal tap 8, at most two positions either way
    },
}


def allowed_range(sector: str, tag_name: str) -> Optional[Tuple[int, int]]:
    """The (lowest, highest) raw value the director may set, or None if it may not touch the tag."""
    return ADJUSTABLE_SETPOINTS.get(sector, {}).get(tag_name)
