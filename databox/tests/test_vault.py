import os

import pytest

from databox.vault import Guard, IntegrityError, Vault, VaultFrozen, shannon_entropy

TEXT = ("asset,type,location\n" + "P-001,pump,Station 3\n" * 80).encode()


def test_versions_are_kept_and_readable(tmp_path):
    vault = Vault(tmp_path)
    first = vault.put("a.csv", b"one")
    second = vault.put("a.csv", b"two")
    assert (first.version, second.version) == (1, 2)
    assert vault.get("a.csv") == b"two"
    assert vault.get("a.csv", 1) == b"one"


def test_unchanged_content_is_not_stored_twice(tmp_path):
    vault = Vault(tmp_path)
    vault.put("a.csv", b"same")
    vault.put("a.csv", b"same")
    assert len(vault.history("a.csv")) == 1


def test_nothing_is_overwritten(tmp_path):
    vault = Vault(tmp_path)
    vault.put("a.csv", b"one")
    objects = tmp_path / "objects"
    first_object = next(objects.iterdir())
    before = first_object.read_bytes()
    vault.put("a.csv", b"two")
    assert len(list(objects.iterdir())) == 2
    assert first_object.read_bytes() == before


def test_plaintext_never_touches_disk(tmp_path):
    vault = Vault(tmp_path)
    vault.put("secret.txt", b"substation-7 access code")
    for obj in (tmp_path / "objects").iterdir():
        assert b"substation-7" not in obj.read_bytes()


def test_tampered_object_is_detected(tmp_path):
    vault = Vault(tmp_path)
    vault.put("a.csv", TEXT)
    obj = next((tmp_path / "objects").iterdir())
    data = bytearray(obj.read_bytes())
    data[20] ^= 0xFF
    obj.write_bytes(bytes(data))
    with pytest.raises(IntegrityError):
        vault.get("a.csv")


def test_state_survives_a_restart(tmp_path):
    vault = Vault(tmp_path)
    vault.put("a.csv", b"one")
    vault.put("a.csv", b"two")
    vault.freeze("test")
    reopened = Vault(tmp_path)
    assert reopened.get("a.csv", 1) == b"one"
    assert reopened.frozen and reopened.freeze_reason == "test"


def test_state_digest_follows_newest_versions(tmp_path):
    vault = Vault(tmp_path)
    vault.put("a.csv", b"one")
    before = vault.state_digest()
    vault.put("a.csv", b"two")
    assert vault.state_digest() != before


def test_entropy_separates_text_from_encrypted():
    assert shannon_entropy(TEXT) < 6.0
    assert shannon_entropy(os.urandom(4096)) > 7.5


def test_frozen_vault_refuses_until_unfrozen(tmp_path):
    vault = Vault(tmp_path, guard=Guard(entropy_jumps=3))
    names = [f"f{i}.csv" for i in range(20)]
    for name in names:
        vault.put(name, TEXT)
    vault.put(names[0], os.urandom(len(TEXT)))
    vault.put(names[1], os.urandom(len(TEXT)))
    with pytest.raises(VaultFrozen):
        vault.put(names[2], os.urandom(len(TEXT)))
    with pytest.raises(VaultFrozen):
        vault.put(names[3], TEXT + b"x")
    assert vault.history(names[2])[-1].version == 1   # the trigger write was refused
    vault.unfreeze("operator")
    vault.put(names[3], TEXT + b"x")
