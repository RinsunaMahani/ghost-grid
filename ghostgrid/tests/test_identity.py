"""Unit tests for GhostGrid identity generation and persistence."""
import os
import tempfile
import unittest
from ghostgrid.core.identity import (
    generate_site_identity,
    save_identity,
    load_identity,
    VENDOR_OUIS,
)


class TestIdentity(unittest.TestCase):

    def test_random_seeds_produce_unique_identities(self):
        """Two different random seeds must produce different personas and register layouts."""
        id1 = generate_site_identity(sector="water", seed="seed-alpha-101")
        id2 = generate_site_identity(sector="water", seed="seed-bravo-202")

        # Must have different MAC addresses
        self.assertNotEqual(id1.mac_address, id2.mac_address)

        # Must have different serial numbers
        self.assertNotEqual(id1.serial_number, id2.serial_number)

        # Relative register layout addresses must differ across seeds
        id1_offsets = [t.address for t in id1.tags.values() if not t.is_honeytoken]
        id2_offsets = [t.address for t in id2.tags.values() if not t.is_honeytoken]
        self.assertNotEqual(id1_offsets, id2_offsets, "Normal tags must have randomized relative layout offsets per seed")

        # Honeytoken addresses or values must differ across seeds
        ht1 = [t for t in id1.tags.values() if t.is_honeytoken]
        ht2 = [t for t in id2.tags.values() if t.is_honeytoken]
        self.assertTrue(len(ht1) > 0)
        self.assertTrue(len(ht2) > 0)

        # Compare holding register honeytokens
        ht1_hr = [t for t in ht1 if t.reg_type.value == "holding_register"][0]
        ht2_hr = [t for t in ht2 if t.reg_type.value == "holding_register"][0]
        self.assertNotEqual(ht1_hr.default_value, ht2_hr.default_value)

    def test_vendor_oui_mac_matching(self):
        """Generated MAC addresses must strictly use the OUI assigned to the selected vendor."""
        for vendor in ("Schneider Electric", "Siemens", "Rockwell Automation", "ABB"):
            ident = generate_site_identity(sector="water", vendor=vendor, seed=f"test-oui-{vendor}")
            oui_part = ident.mac_address[:8]
            valid_ouis = VENDOR_OUIS.get(vendor, [])
            self.assertIn(oui_part, valid_ouis, f"Vendor {vendor} MAC {ident.mac_address} has invalid OUI {oui_part}")

    def test_occupied_address_set_differs_between_installs(self):
        """A scanner mapping which addresses answer must not see the same layout on every decoy."""
        for sector in ("water", "power"):
            layouts = set()
            for i in range(50):
                ident = generate_site_identity(sector=sector, seed=f"layout-{sector}-{i}")
                layouts.add(tuple(sorted((t.reg_type.value, t.address)
                                         for t in ident.tags.values() if not t.is_honeytoken)))
            self.assertGreater(len(layouts), 45, f"{sector}: only {len(layouts)} distinct address sets in 50 installs")

    def test_no_two_tags_share_an_address(self):
        for sector in ("water", "power"):
            for i in range(100):
                ident = generate_site_identity(sector=sector, seed=f"unique-{sector}-{i}")
                keys = [(t.reg_type, t.address) for t in ident.tags.values()]
                self.assertEqual(len(keys), len(set(keys)), f"{sector} seed {i} has overlapping addresses")

    def test_neutral_fictional_facility_names_across_seeds(self):
        """Default generated facility names must be neutral and not impersonate real utilities or real facilities."""
        real_names = [
            "Rand Water", "Eskom", "City Power", "Amatola",
            "Mapleton", "Palmiet", "Eikenhof", "Roodeplaat",
            "Camden", "Apollo", "Minerva", "Fordsburg", "Cydna"
        ]

        for i in range(50):
            w_id = generate_site_identity(sector="water", seed=f"water-fictional-{i}")
            p_id = generate_site_identity(sector="power", seed=f"power-fictional-{i}")

            for real in real_names:
                self.assertNotIn(real.lower(), w_id.site_name.lower(), f"Water site name '{w_id.site_name}' contains real entity '{real}'")
                self.assertNotIn(real.lower(), p_id.site_name.lower(), f"Power site name '{p_id.site_name}' contains real entity '{real}'")

    def test_sector_power_identity(self):
        """Power sector decoy must have an electrical substation name and tags."""
        ident = generate_site_identity(sector="power", seed="power-site-seed")
        self.assertEqual(ident.sector, "power")
        self.assertIn("Substation", ident.site_name)
        self.assertIn("FEEDER_1_CB_CMD", ident.tags)
        self.assertNotIn("PUMP_1_CMD", ident.tags)

    def test_identity_persistence(self):
        """Identity saved to disk must reload identically on restart."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            id_path = os.path.join(tmp_dir, "test_ident.json")
            original = generate_site_identity(sector="water", seed="persist-seed-1")
            save_identity(original, id_path)

            loaded = load_identity(id_path)
            self.assertIsNotNone(loaded)
            self.assertEqual(loaded.site_name, original.site_name)
            self.assertEqual(loaded.mac_address, original.mac_address)
            self.assertEqual(loaded.serial_number, original.serial_number)
            self.assertEqual(len(loaded.tags), len(original.tags))


if __name__ == "__main__":
    unittest.main()
