import os

from databox.restore import main as restore_main
from databox.vault import Guard, Vault, VaultFrozen, find_suspects, restore_suspects
from databox.vault.recovery import CHANGED_BEFORE_FREEZE, LOOKS_ENCRYPTED

SMALL = b"site ok\n" * 30                                   # 240 bytes: too small to look encrypted
LARGE = ("asset,type\n" + "P-001,pump\n" * 150).encode()   # about 1.7 KB of plain text


def encrypt_until_frozen(vault, names):
    stored = []
    for name in names:
        try:
            vault.put(name, os.urandom(vault.latest(name).size))
            stored.append(name)
        except VaultFrozen:
            break
    return stored


def small_vault_after_attack(path):
    vault = Vault(path, guard=Guard())
    names = [f"notes/site-{i:02d}.txt" for i in range(20)]
    for name in names:
        vault.put(name, SMALL)
    return vault, encrypt_until_frozen(vault, names)


def test_small_files_changed_before_the_freeze_are_suspects(tmp_path):
    # Regression: small encrypted files never reach the entropy cutoff, so they used to be missed.
    vault, stored = small_vault_after_attack(tmp_path)
    assert vault.frozen and len(stored) == 5   # mass-change limit is 6, so 5 got in
    suspects = find_suspects(vault)
    assert sorted(s.name for s in suspects) == sorted(stored)
    assert all(s.reason == CHANGED_BEFORE_FREEZE and s.clean_version == 1 for s in suspects)


def test_encrypted_looking_file_outside_a_freeze_is_a_suspect(tmp_path):
    vault = Vault(tmp_path)   # no guard, never frozen
    vault.put("assets/register.csv", LARGE)
    vault.put("assets/register.csv", os.urandom(len(LARGE)))
    [suspect] = find_suspects(vault)
    assert (suspect.reason, suspect.bad_version, suspect.clean_version) == (LOOKS_ENCRYPTED, 2, 1)


def test_rollback_restores_clean_data_and_keeps_the_evidence(tmp_path):
    vault, stored = small_vault_after_attack(tmp_path)
    restored = restore_suspects(vault, "operator")
    assert len(restored) == len(stored)
    for name in stored:
        assert vault.get(name) == SMALL
        assert [v.version for v in vault.history(name)] == [1, 2, 3]   # original, damaged, restored
    assert find_suspects(vault) == []


def test_restore_tool_end_to_end(tmp_path):
    vault, stored = small_vault_after_attack(tmp_path)
    del vault

    assert restore_main(["--vault", str(tmp_path)]) == 0                                   # review changes nothing
    assert Vault(tmp_path).frozen
    assert restore_main(["--vault", str(tmp_path), "--unfreeze", "--operator", "op"]) == 1  # files still need rolling back
    assert restore_main(["--vault", str(tmp_path), "--apply"]) == 2                         # an operator name is required
    assert restore_main(["--vault", str(tmp_path), "--apply", "--unfreeze", "--operator", "op"]) == 0

    vault = Vault(tmp_path)
    assert not vault.frozen
    assert all(vault.get(name) == SMALL for name in stored)
