"""Scenario Director runtime engine for GhostGrid.

Background autonomous process that periodically updates operational storylines,
adds subtle realistic process drift, and logs narrative events to the SOC database.
Validates all adjustments for type and range before applying to prevent corrupt state.
Guarantees that the director never flips command coils or safety trips.
"""
import logging
import threading
import time
from typing import Dict, Any, Optional
from ghostgrid.core.identity import SiteIdentity, RegisterType
from ghostgrid.core.state import StateEngine
from ghostgrid.core.logger import EventLogger
from ghostgrid.core.director.llm_client import LLMClient

logger = logging.getLogger("ghostgrid.director")

# Critical command coils and safety interlocks that the director is strictly forbidden to flip
DISALLOWED_DIRECTOR_TAGS = {
    "PUMP_1_CMD", "PUMP_2_CMD", "EMERGENCY_SHUTDOWN_CMD", "OUTLET_VALVE_CMD",
    "CHLORINE_DOSING_CMD", "INCOMING_BREAKER_CMD", "FEEDER_1_BREAKER_CMD",
    "FEEDER_2_BREAKER_CMD", "BUS_COUPLER_CMD", "AUTO_RECLOSE_ARMED",
    "PUMP_1_RUNNING", "PUMP_2_RUNNING", "OUTLET_VALVE_OPEN", "CHLORINE_DOSING_ACTIVE",
    "HIGH_LEVEL_TRIP", "LOW_LEVEL_TRIP", "DRY_RUN_TRIP", "EMERGENCY_SHUTDOWN_ACTIVE",
    "INCOMING_BREAKER_CLOSED", "FEEDER_1_CLOSED", "FEEDER_2_CLOSED", "BUS_COUPLER_CLOSED",
    "OVERCURRENT_TRIP", "EARTH_FAULT_TRIP", "UNDERFREQUENCY_STAGE1_TRIP", "BUCHHOLZ_GAS_ALARM",
}


class ScenarioDirector:
    """Orchestrates periodic operational storyline generation and state adjustment."""

    def __init__(
        self,
        identity: SiteIdentity,
        state_engine: StateEngine,
        event_logger: EventLogger,
        llm_client: LLMClient,
        interval_seconds: int = 60,
        enabled: bool = True,
    ):
        self.identity = identity
        self.state = state_engine
        self.logger = event_logger
        self.llm = llm_client
        self.interval_seconds = interval_seconds
        self.enabled = enabled

        self._running = False
        self._thread: Optional[threading.Thread] = None

    def start(self):
        """Start the background storyline generation thread."""
        if not self.enabled:
            logger.info("Scenario Director is disabled by configuration.")
            return

        self._running = True
        self._thread = threading.Thread(
            target=self._run_loop,
            daemon=True,
            name="GhostGrid-ScenarioDirector",
        )
        self._thread.start()
        logger.info("Scenario Director started (interval=%ds, provider=%s)", self.interval_seconds, self.llm.provider)

    def stop(self):
        """Stop the background director thread."""
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
            logger.info("Scenario Director stopped.")

    def _run_loop(self):
        # Generate initial storyline immediately on startup
        self._step()

        while self._running:
            time.sleep(self.interval_seconds)
            if self._running:
                self._step()

    def _step(self):
        """Execute one cycle of scenario analysis and storyline generation."""
        try:
            # 1. Gather high-level attacker reconnaissance stats (sanitized, no raw input)
            metrics = self.logger.get_soc_metrics()
            active_sessions = metrics.get("active_sessions", 0)
            total_requests = metrics.get("total_requests", 0)
            total_writes = metrics.get("total_writes", 0)

            has_recent_activity = (total_requests > 0)
            probes_summary = (
                f"Active connections: {active_sessions}. "
                f"Total requests logged: {total_requests}. "
                f"Total write commands: {total_writes}."
            )

            # 2. Get current state snapshot
            snapshot = self.state.get_snapshot()

            # 3. Request next storyline from LLM / offline engine
            storyline = self.llm.generate_storyline(
                site_name=self.identity.site_name,
                sector=self.identity.sector,
                current_state=snapshot,
                recent_probes_summary=probes_summary,
                has_recent_activity=has_recent_activity,
            )

            title = storyline.get("title", "Standard SCADA Supervisory Loop")
            narrative = storyline.get("narrative", "Routine telemetry polling across all drop points.")
            adjustments = storyline.get("adjustments", {})

            # 4. Safely apply non-destructive operational adjustments with strict validation
            for tag_name, val in adjustments.items():
                if tag_name in DISALLOWED_DIRECTOR_TAGS:
                    logger.debug("Scenario Director blocked from modifying critical tag '%s'", tag_name)
                    continue

                tag = self.identity.tags.get(tag_name)
                if not tag or tag.is_honeytoken or tag.read_only:
                    continue

                # Director is only permitted to adjust holding registers (setpoints, thresholds, tap positions)
                if tag.reg_type != RegisterType.HOLDING_REGISTER:
                    logger.debug("Scenario Director skipped non-holding-register tag '%s'", tag_name)
                    continue

                try:
                    clean_val = int(val)
                    if 0 <= clean_val <= 65535:
                        self.state.update_tag_value(tag_name, clean_val)
                except (ValueError, TypeError):
                    continue

            # 5. Persist storyline in database for SOC dashboard
            self.logger.log_storyline(title, narrative, adjustments)
            logger.info("Scenario Director updated storyline: '%s'", title)

        except Exception as e:
            logger.error("Error in Scenario Director step: %s", e, exc_info=True)
