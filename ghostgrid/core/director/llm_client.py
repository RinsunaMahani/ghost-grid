"""LLM Client for the GhostGrid Scenario Director.

Connects to a local Ollama instance (or returns realistic offline storylines)
to generate believable operational narratives and telemetry adjustments.
Hardened prompts ensure attacker payloads never leak into LLM prompts.
"""
import json
import logging
import requests
from typing import Dict, Any, Optional

from ghostgrid.core.director.limits import ADJUSTABLE_SETPOINTS

logger = logging.getLogger("ghostgrid.director")

# Neutral South African operational narratives
NEUTRAL_WATER_STORYLINES = [
    {
        "title": "Municipal Morning Peak Demand Surge",
        "narrative": "Regional distribution reservoirs reported morning drawdowns. Increased main intake flow setpoint to replenish buffer storage while keeping discharge pressure stable.",
        "adjustments": {"LEVEL_SETPOINT_PCT": 820, "PRESSURE_SETPOINT_BAR": 640},
    },
    {
        "title": "Raw Water Quality & Turbidity Shift",
        "narrative": "Rainfall in the upper catchment elevated raw river turbidity. Dosing rate adjusted to maintain SANS 241 compliance target residual.",
        "adjustments": {"DOSING_RATE_L_HR": 52},
    },
    {
        "title": "High-Pressure Delivery Header Stabilization",
        "narrative": "Minor pressure pulsation detected on municipal booster main. Delivery header pressure setpoint adjusted down by 0.2 bar to protect joint seals.",
        "adjustments": {"PRESSURE_SETPOINT_BAR": 610},
    },
    {
        "title": "Routine Off-Peak Energy Storage Rebalance",
        "narrative": "Off-peak pumping window initiated to fill distribution reservoirs ahead of evening industrial demand peak.",
        "adjustments": {"LEVEL_SETPOINT_PCT": 850},
    },
]

NEUTRAL_POWER_STORYLINES = [
    {
        "title": "Industrial Feeder Load Ramping",
        "narrative": "Heavy industrial manufacturing load commenced shift ramping on Feeder 1. Transformer temperature rose within normal thermal limits.",
        "adjustments": {"VOLTAGE_REGULATOR_TAP": 9},
    },
    {
        "title": "VAr Compensation & Power Factor Optimization",
        "narrative": "Substation power factor drifted slightly. Switched capacitor bank steps to maintain reactive power balance within national grid code tolerances.",
        "adjustments": {"VOLTAGE_REGULATOR_TAP": 8},
    },
    {
        "title": "Grid Frequency Stabilization Cycle",
        "narrative": "National system frequency experienced transient excursion due to regional generator trip. Secondary frequency regulation active.",
        # Narrative only: under-frequency load-shed settings are protection settings, not operations.
        "adjustments": {},
    },
    {
        "title": "Transformer Night Cooling Cycle",
        "narrative": "Substation loading eased during late evening hours. Ambient cooling reduced transformer winding temperature.",
        "adjustments": {"VOLTAGE_REGULATOR_TAP": 7},
    },
]


class LLMClient:
    """Interface to local AI runtime (Ollama) with deterministic fallback."""

    def __init__(
        self,
        provider: str = "mock",
        model: str = "qwen2.5:1.5b",
        endpoint: str = "http://localhost:11434",
        hardened: bool = True,
    ):
        self.provider = provider.lower()
        self.model = model
        self.endpoint = endpoint.rstrip("/")
        self.hardened = hardened
        self._offline_index = 0

    def generate_storyline(
        self,
        site_name: str,
        sector: str,
        current_state: Dict[str, Any],
        recent_probes_summary: str,
        has_recent_activity: bool = False,
    ) -> Dict[str, Any]:
        """Generate a realistic operational storyline for the active decoy."""
        if self.provider == "ollama":
            res = self._call_ollama(site_name, sector, current_state, recent_probes_summary)
            if res:
                return res

        return self._generate_offline_storyline(sector, has_recent_activity=has_recent_activity)

    def _call_ollama(
        self,
        site_name: str,
        sector: str,
        current_state: Dict[str, Any],
        recent_probes_summary: str,
    ) -> Optional[Dict[str, Any]]:
        url = f"{self.endpoint}/api/generate"

        # The same ranges the director enforces, so a suggestion can actually be applied.
        choices = "; ".join(f"{name} {low}-{high}"
                            for name, (low, high) in ADJUSTABLE_SETPOINTS.get(sector, {}).items())
        system_prompt = (
            f"You are the SCADA Operations AI Director for a {sector} facility in South Africa called '{site_name}'. "
            "Write a brief 1-sentence believable daily SCADA log entry explaining routine operations. "
            f'You may include one small setpoint change in "adjustments", using only these tags and raw values: {choices}. '
            'Return JSON only: {"title": "string", "narrative": "string", "adjustments": {}}'
        )

        user_prompt = (
            f"Facility: {site_name}. Current status: {recent_probes_summary}. "
            "Produce an authentic operational shift update."
        )

        payload = {
            "model": self.model,
            "system": system_prompt,
            "prompt": user_prompt,
            "format": "json",
            "stream": False,
            "options": {"temperature": 0.7, "num_predict": 250},
        }

        try:
            resp = requests.post(url, json=payload, timeout=5.0)
            if resp.status_code == 200:
                body = resp.json()
                raw_response = body.get("response", "")
                parsed = json.loads(raw_response)
                if "title" in parsed and "narrative" in parsed:
                    return {
                        "title": parsed["title"],
                        "narrative": parsed["narrative"],
                        "adjustments": parsed.get("adjustments", {}),
                    }
        except Exception as e:
            logger.info("Ollama AI Director unavailable (%s). Using authentic built-in storylines.", e)

        return None

    def _generate_offline_storyline(self, sector: str, has_recent_activity: bool = False) -> Dict[str, Any]:
        """Produce realistic built-in operational narratives."""
        pool = NEUTRAL_WATER_STORYLINES if sector == "water" else NEUTRAL_POWER_STORYLINES
        item = pool[self._offline_index % len(pool)]
        self._offline_index += 1

        storyline = dict(item)
        if has_recent_activity:
            storyline["narrative"] += " Remote telemetry supervisory scan completed nominal poll."

        return storyline
