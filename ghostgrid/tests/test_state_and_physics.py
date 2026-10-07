"""Unit tests for GhostGrid physical simulations and state engine."""
import unittest
from ghostgrid.core.identity import generate_site_identity
from ghostgrid.profiles.water.simulation import WaterProfile
from ghostgrid.profiles.power.simulation import PowerProfile


class TestStateAndPhysics(unittest.TestCase):

    def test_water_simulation_mass_balance_and_level_setpoint_control(self):
        """Reservoir level must stabilize around LEVEL_SETPOINT_PCT (80.0%) and not reach 100% or drain."""
        ident = generate_site_identity(sector="water", seed="water-sim-mb")
        profile = WaterProfile(ident, noise_amplitude=0.0)
        state = profile.initialize_state()

        # Setpoint is 80.0% (800)
        state["LEVEL_SETPOINT_PCT"] = 800
        state["PUMP_1_CMD"] = 1
        state["VALVE_INLET_CMD"] = 1
        state["VALVE_DISCHARGE_CMD"] = 1
        state["EMERGENCY_SHUTDOWN_CMD"] = 0

        # Simulate 12 hours (43,200 seconds) in 1-second steps
        # Pump 1 cycles on and off around the setpoint, so whether it runs at one given second
        # is down to timing. Count how long it ran over the last hour instead.
        ran = 0
        for i in range(43200):
            state = profile.step(dt=1.0, current_state=state)
            if i >= 43200 - 3600:
                ran += state["PUMP_1_RUNNING"]

        final_level = state["RESERVOIR_LEVEL_PCT"]
        # Level should be tightly controlled around 80.0% (between 78.0% and 82.0%), not 100% and not empty!
        self.assertTrue(780 <= final_level <= 820, f"Reservoir level not controlled: {final_level / 10.0}%")
        self.assertGreater(ran, 0, "Pump 1 never ran in the last hour, so the level isn't being controlled")
        self.assertEqual(state["RESERVOIR_HIGH_SWITCH"], 0)
        self.assertEqual(state["RESERVOIR_LOW_SWITCH"], 0)
        self.assertEqual(state["PUMP_1_TRIP"], 0)

    def test_water_booster_pump_operation(self):
        """Enabling booster Pump 2 must increase flow by ~1,100 m3/h."""
        ident = generate_site_identity(sector="water", seed="water-p2-test")
        profile = WaterProfile(ident, noise_amplitude=0.0)
        state = profile.initialize_state()

        # Pump 1 only
        state["PUMP_1_CMD"] = 1
        state["PUMP_2_CMD"] = 0
        s1 = profile.step(dt=1.0, current_state=state)
        inflow_p1 = s1["INFLOW_RATE_M3H"]

        # Pump 1 + Pump 2
        state["PUMP_2_CMD"] = 1
        s2 = profile.step(dt=1.0, current_state=state)
        inflow_p1_p2 = s2["INFLOW_RATE_M3H"]

        self.assertEqual(s2["PUMP_2_RUNNING"], 1)
        self.assertGreater(inflow_p1_p2, inflow_p1 + 900, "Pump 2 booster must significantly increase inflow")

    def test_water_dry_run_trip_precedence(self):
        """When reservoir drops below alarm limit, low level trip must trip pump and set inflow to 0."""
        ident = generate_site_identity(sector="water", seed="water-dry-run")
        profile = WaterProfile(ident, noise_amplitude=0.0)
        state = profile.initialize_state()

        # Force level below low alarm limit (e.g. 10%)
        profile.level_pct = 10.0
        state["RESERVOIR_LEVEL_PCT"] = 100
        state["PUMP_1_CMD"] = 1

        state = profile.step(dt=1.0, current_state=state)

        self.assertEqual(state["RESERVOIR_LOW_SWITCH"], 1)
        self.assertEqual(state["PUMP_1_TRIP"], 1)
        self.assertEqual(state["PUMP_1_RUNNING"], 0)
        self.assertEqual(state["INFLOW_RATE_M3H"], 0)

    def test_power_simulation_physics_and_calibrated_baseline(self):
        """Power profile baseline active power must remain ~46.2 MW with zero tick-1 jump."""
        ident = generate_site_identity(sector="power", seed="power-sim-test")
        profile = PowerProfile(ident, noise_amplitude=0.0)
        state = profile.initialize_state()

        state["FEEDER_1_CB_CMD"] = 1
        state["FEEDER_2_CB_CMD"] = 1
        next_state = profile.step(dt=1.0, current_state=state)

        self.assertEqual(next_state["FEEDER_1_CB_STATUS"], 1)
        self.assertEqual(next_state["FEEDER_2_CB_STATUS"], 1)

        # Baseline feeder current ~175 A
        self.assertTrue(150 <= next_state["FEEDER_1_CURRENT_A"] <= 200)

        # Active power P = sqrt(3) * V * I * pf / 1000 = ~46.2 MW
        # Must be in 45.0 - 47.5 MW range, NOT 84.8 MW!
        p_mw = next_state["ACTIVE_POWER_MW"] / 10.0
        self.assertTrue(45.0 <= p_mw <= 47.5, f"Active power jump detected: {p_mw} MW")

        # Buchholz relay must NOT trip from normal temperature
        self.assertEqual(next_state["TRANSFORMER_BUCHHOLZ_ALARM"], 0)

        # Open breaker -> instantaneous zero current
        tripped_state = profile.handle_write("FEEDER_1_CB_CMD", 0, next_state)
        step_tripped = profile.step(dt=1.0, current_state=tripped_state)
        self.assertEqual(step_tripped["FEEDER_1_CB_STATUS"], 0)
        self.assertEqual(step_tripped["FEEDER_1_CURRENT_A"], 0)

    def test_power_buchholz_fault_isolation(self):
        """Buchholz gas alarm must trigger on internal electrical fault, NOT temperature."""
        ident = generate_site_identity(sector="power", seed="power-buchholz")
        profile = PowerProfile(ident, noise_amplitude=0.0)
        state = profile.initialize_state()

        # High transformer temperature must NOT trigger Buchholz
        profile.transformer_temp_c = 95.0
        s1 = profile.step(dt=1.0, current_state=state)
        self.assertEqual(s1["TRANSFORMER_BUCHHOLZ_ALARM"], 0, "Buchholz gas alarm should not be driven by temperature")

        # Earth fault alarm DOES trip Buchholz
        state["EARTH_FAULT_ALARM"] = 1
        s2 = profile.step(dt=1.0, current_state=state)
        self.assertEqual(s2["TRANSFORMER_BUCHHOLZ_ALARM"], 1, "Buchholz gas alarm should trip on internal earth fault")


if __name__ == "__main__":
    unittest.main()
