"""Unit tests for the Scenario Director and LLM client."""
import os
import tempfile
import unittest
from ghostgrid.core.identity import generate_site_identity, RegisterType
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


if __name__ == "__main__":
    unittest.main()
