from dataclasses import replace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from databox.loop import ChainSigner, ChainVerifier, Frame, FrameError

KEY = Ed25519PrivateKey.generate()


def frames(n):
    signer = ChainSigner(KEY)
    return [signer.next_frame(f'{{"n":{i}}}'.encode()) for i in range(n)]


def kinds(check):
    return [kind for kind, _ in check.problems]


def test_genuine_chain_is_accepted():
    verifier = ChainVerifier(KEY.public_key())
    assert all(verifier.check(f).accepted for f in frames(5))


def test_encode_decode_roundtrip():
    f = frames(1)[0]
    assert Frame.decode(f.encode()) == f
    with pytest.raises(FrameError):
        Frame.decode(b"not a frame at all" * 10)


def test_second_copy_from_the_diode_is_a_duplicate():
    verifier = ChainVerifier(KEY.public_key())
    f = frames(1)[0]
    verifier.check(f)
    check = verifier.check(f)
    assert check.duplicate and not check.problems


def test_altered_payload_fails_the_signature():
    verifier = ChainVerifier(KEY.public_key())
    f = frames(1)[0]
    assert kinds(verifier.check(replace(f, payload=b'{"n":99}'))) == ["bad signature"]


def test_frame_signed_by_another_key_is_rejected():
    verifier = ChainVerifier(KEY.public_key())
    forged = ChainSigner(Ed25519PrivateKey.generate()).next_frame(b"{}")
    check = verifier.check(forged)
    assert kinds(check) == ["bad signature"] and not check.accepted


def test_missing_frame_shows_as_a_gap():
    verifier = ChainVerifier(KEY.public_key())
    f1, _, f3 = frames(3)
    verifier.check(f1)
    assert kinds(verifier.check(f3)) == ["gap"]


def test_altered_frame_is_not_reported_again_as_a_gap():
    """The bad-signature alarm already covers it: the next genuine frame mustn't add a second alarm."""
    verifier = ChainVerifier(KEY.public_key())
    f1, f2, f3 = frames(3)
    verifier.check(f1)
    assert kinds(verifier.check(replace(f2, payload=b'{"n":99}'))) == ["bad signature"]
    check = verifier.check(f3)
    assert check.accepted and not check.problems


def test_second_copy_of_an_altered_frame_is_one_alarm_not_two():
    verifier = ChainVerifier(KEY.public_key())
    bad = replace(frames(1)[0], payload=b'{"n":99}')
    assert kinds(verifier.check(bad)) == ["bad signature"]
    again = verifier.check(bad)
    assert again.duplicate and not again.problems


def test_gap_still_counts_frames_that_were_never_seen():
    verifier = ChainVerifier(KEY.public_key())
    f1, f2, _, f4 = frames(4)
    verifier.check(f1)
    verifier.check(replace(f2, payload=b'{"n":99}'))       # #2 altered and reported; #3 simply lost
    check = verifier.check(f4)
    assert kinds(check) == ["gap"] and check.problems[0][1].startswith("1 frame(s)")


def test_valid_signature_but_wrong_link_is_a_chain_break():
    verifier = ChainVerifier(KEY.public_key())
    f1 = frames(1)[0]
    verifier.check(f1)
    unsigned = Frame(2, f1.sent_ns, b"\x01" * 32, b"{}")
    wrong_link = replace(unsigned, signature=KEY.sign(unsigned.body()))
    assert kinds(verifier.check(wrong_link)) == ["chain break"]


def test_old_frame_sent_again_later_is_a_replay():
    verifier = ChainVerifier(KEY.public_key(), duplicate_window_s=0)
    fs = frames(3)
    for f in fs:
        verifier.check(f)
    assert kinds(verifier.check(fs[0])) == ["replay"]


def test_monitor_starting_mid_stream_syncs_without_alarm():
    verifier = ChainVerifier(KEY.public_key())
    later = frames(10)[5]
    check = verifier.check(later)
    assert check.accepted and not check.problems
