"""Scenario Director runtime engine for GhostGrid.

Background autonomous process that periodically updates operational storylines,
adds subtle realistic process drift, and logs narrative events to the SOC database.
Only allow-listed operational setpoints can change, each inside a plausible operating range
(see limits.py), so the director can never flip a command coil, cause a safety trip, or move an
alarm limit or protection setting that would trip something indirectly.
"""
import logging
import threading
import time
from typing import Optional
from ghostgrid.core.identity import SiteIdentity, RegisterType
from ghostgrid.core.state import StateEngine
from ghostgrid.core.logger import EventLogger
from ghostgrid.core.director.limits import allowed_range
from ghostgrid.core.director.llm_client import LLMClient

logger = logging.getLogger("ghostgrid.director")

# Storyline text from a local model is shown on the SOC console; keep it to log-entry length.
MAX_TITLE_CHARS = 120
MAX_NARRATIVE_CHARS = 600


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

            # A local model can return anything: keep the text short and plain, and ignore
            # adjustments that aren't a mapping.
            title = str(storyline.get("title") or "Standard SCADA Supervisory Loop")[:MAX_TITLE_CHARS]
            narrative = str(storyline.get("narrative")
                            or "Routine telemetry polling across all drop points.")[:MAX_NARRATIVE_CHARS]
            adjustments = storyline.get("adjustments")
            if not isinstance(adjustments, dict):
                adjustments = {}

            # 4. Apply only allowed setpoint changes, each inside its operating range
            applied = {}
            for tag_name, val in adjustments.items():
                band = allowed_range(self.identity.sector, tag_name)
                tag = self.identity.tags.get(tag_name)
                # Defence in depth: the allow-list only names setpoints, but check the tag itself too.
                if (band is None or not tag or tag.is_honeytoken or tag.read_only
                        or tag.reg_type != RegisterType.HOLDING_REGISTER):
                    logger.debug("Scenario Director may not change '%s'; ignored", tag_name)
                    continue
                try:
                    clean_val = int(val)
                except (ValueError, TypeError, OverflowError):
                    continue
                lowest, highest = band
                if not lowest <= clean_val <= highest:
                    logger.debug("Scenario Director value %s for '%s' is outside %s-%s; ignored",
                                 clean_val, tag_name, lowest, highest)
                    continue
                self.state.update_tag_value(tag_name, clean_val)
                applied[tag_name] = clean_val

            # 5. Persist the storyline and what actually changed, for the SOC dashboard
            self.logger.log_storyline(title, narrative, applied)
            logger.info("Scenario Director updated storyline: '%s'", title)

        except Exception as e:
            logger.error("Error in Scenario Director step: %s", e, exc_info=True)
