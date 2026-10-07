"""Unit tests for the Scenario Director and LLM client."""
import os
import tempfile
import unittest
from ghostgrid.core.identity import generate_site_identity
from ghostgrid.core.director.llm_client import LLMClient
from ghostgrid.core.director import ScenarioDirector
from ghostgrid.core.state import StateEngine
from ghostgrid.profiles.water.simulation import WaterProfile
from ghostgrid.core.logger import EventLogger


class TestDirector(unittest.TestCase):

    def test_offline_storyline_generation_activity_flag(self):
        """Offline storyline only appends scan activity note when recent activity actually occurred."""
        client = LLMClient(provider="mock")
        # Without activity
        res_no_act = client.generate_storyline(
            site_name="District 4 Bulk Water",
            sector="water",
            current_state={},
            recent_probes_summary="Active connections: 0. Total requests logged: 0.",
            has_recent_activity=False,
        )
        self.assertIn("title", res_no_act)
        self.assertIn("narrative", res_no_act)
        self.assertNotIn("Remote telemetry supervisory scan", res_no_act["narrative"])

        # With activity
        res_act = client.generate_storyline(
            site_name="District 4 Bulk Water",
            sector="water",
            current_state={},
            recent_probes_summary="Active connections: 1. Total requests logged: 15.",
            has_recent_activity=True,
        )
        self.assertIn("Remote telemetry supervisory scan completed nominal poll.", res_act["narrative"])

    def test_director_adjustment_validation_and_safety_interlocks(self):
        """Director must NEVER flip command coils or safety trips, and can only adjust setpoints."""
        ident = generate_site_identity(sector="water", seed="dir-test-01")
        profile = WaterProfile(ident, noise_amplitude=0.0)
        engine = StateEngine(ident, profile)

        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp_dir:
            db_path = os.path.join(tmp_dir, "dir_test.db")
            logger = EventLogger(db_path)

            class MockLLMClient(LLMClient):
                def generate_storyline(self, site_name, sector, current_state, recent_probes_summary, has_recent_activity=False):
                    return {
                        "title": "Adversary Injection Test",
                        "narrative": "Attempting unauthorized state change through director.",
                        "adjustments": {
                            "PUMP_1_CMD": 0,                    # FORBIDDEN: Command coil
                            "EMERGENCY_SHUTDOWN_CMD": 1,        # FORBIDDEN: Command coil
                            "DRY_RUN_TRIP": 1,                  # FORBIDDEN: Discrete trip
                            "LEVEL_SETPOINT_PCT": 850,          # ALLOWED: Holding register setpoint
                            "PRESSURE_SETPOINT_BAR": 680,       # ALLOWED: Holding register setpoint
                        },
                    }

            mock_client = MockLLMClient(provider="mock")
            director = ScenarioDirector(
                identity=ident,
                state_engine=engine,
                event_logger=logger,
                llm_client=mock_client,
                enabled=False,
            )

            # Ensure initial states
            self.assertEqual(engine.get_tag_value("PUMP_1_CMD"), 1)
            self.assertEqual(engine.get_tag_value("EMERGENCY_SHUTDOWN_CMD"), 0)

            # Run step
            director._step()

            # Assert forbidden command coils were NOT touched by director
            self.assertEqual(engine.get_tag_value("PUMP_1_CMD"), 1, "Director must not flip PUMP_1_CMD")
            self.assertEqual(engine.get_tag_value("EMERGENCY_SHUTDOWN_CMD"), 0, "Director must not flip EMERGENCY_SHUTDOWN_CMD")

            # Assert allowed holding register setpoints WERE applied
            self.assertEqual(engine.get_tag_value("LEVEL_SETPOINT_PCT"), 850)
            self.assertEqual(engine.get_tag_value("PRESSURE_SETPOINT_BAR"), 680)

            # Assert storyline was logged to database
            logger.flush()
            latest_story = logger.get_latest_storyline()
            self.assertIsNotNone(latest_story)
            self.assertEqual(latest_story["title"], "Adversary Injection Test")

            logger.close()

    def _run_director_with(self, sector, adjustments, seed):
        """One director step with a model that proposes `adjustments`; returns (engine, logged adjustments)."""
        import json
        from ghostgrid.profiles import create_profile

        ident = generate_site_identity(sector=sector, seed=seed)
        engine = StateEngine(ident, create_profile(sector, ident, noise_amplitude=0.0))
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp_dir:
            logger = EventLogger(os.path.join(tmp_dir, "dir.db"))

            class ProposingClient(LLMClient):
                def generate_storyline(self, *args, **kwargs):
                    return {"title": "T" * 500, "narrative": "Shift log.", "adjustments": adjustments}

            ScenarioDirector(identity=ident, state_engine=engine, event_logger=logger,
                             llm_client=ProposingClient(provider="mock"), enabled=False)._step()
            story = logger.get_latest_storyline()
            logger.close()
        self.assertLessEqual(len(story["title"]), 120, "model text must be cut to log-entry length")
        return engine, json.loads(story["adjustments_json"])

    def test_director_never_moves_alarm_limits_or_absurd_setpoints(self):
        """A raised low-level limit would trip the pumps; an absurd setpoint would expose the decoy."""
        engine, logged = self._run_director_with("water", {
            "LOW_LEVEL_ALARM_LIMIT": 900,       # would trip both pumps on dry-run protection
            "HIGH_LEVEL_ALARM_LIMIT": 300,      # alarm limit: off limits
            "LEVEL_SETPOINT_PCT": 65535,        # 6553 %: outside the operating range
            "PRESSURE_SETPOINT_BAR": "640",     # allowed, and a numeric string is fine
        }, seed="dir-limits-01")
        ident_tags = engine.identity.tags
        self.assertEqual(engine.get_tag_value("LOW_LEVEL_ALARM_LIMIT"), ident_tags["LOW_LEVEL_ALARM_LIMIT"].default_value)
        self.assertEqual(engine.get_tag_value("HIGH_LEVEL_ALARM_LIMIT"), ident_tags["HIGH_LEVEL_ALARM_LIMIT"].default_value)
        self.assertEqual(engine.get_tag_value("LEVEL_SETPOINT_PCT"), ident_tags["LEVEL_SETPOINT_PCT"].default_value)
        self.assertEqual(engine.get_tag_value("PRESSURE_SETPOINT_BAR"), 640)
        self.assertEqual(logged, {"PRESSURE_SETPOINT_BAR": 640}, "the SOC log must show only what actually changed")

    def test_director_cannot_trip_a_feeder_through_the_overcurrent_setting(self):
        engine, logged = self._run_director_with("power", {"OVERCURRENT_PICKUP_A": 10, "VOLTAGE_REGULATOR_TAP": 9},
                                                 seed="dir-limits-02")
        state = engine.get_snapshot()
        for _ in range(5):
            state = engine.profile.step(1.0, state)
        self.assertEqual(state["FEEDER_1_CB_STATUS"], 1, "feeder 1 must stay closed")
        self.assertEqual(state["FEEDER_2_CB_STATUS"], 1, "feeder 2 must stay closed")
        self.assertEqual(logged, {"VOLTAGE_REGULATOR_TAP": 9})

    def test_director_ignores_malformed_model_output(self):
        _, logged = self._run_director_with("water", ["not", "a", "mapping"], seed="dir-limits-03")
        self.assertEqual(logged, {})

    def test_every_built_in_storyline_stays_inside_the_allowed_ranges(self):
        """Otherwise a built-in storyline's change would be silently ignored."""
        from ghostgrid.core.director.limits import allowed_range
        from ghostgrid.core.director.llm_client import NEUTRAL_POWER_STORYLINES, NEUTRAL_WATER_STORYLINES

        for sector, pool in (("water", NEUTRAL_WATER_STORYLINES), ("power", NEUTRAL_POWER_STORYLINES)):
            for story in pool:
                for name, value in story["adjustments"].items():
                    band = allowed_range(sector, name)
                    self.assertIsNotNone(band, f"{story['title']}: the director may not change {name}")
                    self.assertTrue(band[0] <= value <= band[1], f"{story['title']}: {name}={value} outside {band}")


if __name__ == "__main__":
    unittest.main()
