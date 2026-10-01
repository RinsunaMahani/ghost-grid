import random

import pytest

from databox.vault import Vault, plant_canaries


def test_planting_is_idempotent_and_hidden_from_legitimate_listing(tmp_path):
    vault = Vault(tmp_path)
    vault.put("assets/register.csv", b"asset,type\nP-001,pump\n")
    planted = plant_canaries(vault, random.Random(1))
    assert len(planted) == 3
    assert plant_canaries(vault, random.Random(2)) == {}
    assert set(planted) <= set(vault.names())
    assert vault.names(include_canaries=False) == ["assets/register.csv"]


def test_opening_a_canary_is_recorded_and_survives_a_restart(tmp_path):
    vault = Vault(tmp_path)
    vault.put("assets/register.csv", b"asset,type\nP-001,pump\n")
    planted = plant_canaries(vault, random.Random(1))
    name = next(iter(planted))

    vault.get("assets/register.csv", reader="backup feed")   # real data: no trip
    data = vault.get(name, reader="console")

    assert planted[name].encode() in data                   # each canary carries its own reference
    assert [(t.name, t.reader) for t in vault.canary_trips()] == [(name, "console")]
    assert [t.name for t in Vault(tmp_path).canary_trips()] == [name]


def test_a_canary_cannot_be_restored_as_if_it_were_data(tmp_path):
    vault = Vault(tmp_path)
    name = next(iter(plant_canaries(vault, random.Random(1))))
    with pytest.raises(ValueError):
        vault.restore(name, 1, "operator")
