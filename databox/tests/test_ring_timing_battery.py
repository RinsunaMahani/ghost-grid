from databox.loop import Frame, FrameRing, LapTimer
from databox.sim import Battery


def frame(seq):
    return Frame(seq, 0, bytes(32), b"{}", bytes(64))


def test_ring_returns_each_frame_once():
    ring = FrameRing(size=8)
    ring.put(frame(1), 100)
    assert ring.take(1)[0].seq == 1
    assert ring.take(1) is None


def test_ring_reports_overdue_frames():
    ring = FrameRing(size=8)
    ring.put(frame(1), 0)
    ring.put(frame(2), 900)
    assert [f.seq for f in ring.overdue(now_mono_ns=1000, timeout_ns=500)] == [1]


def test_ring_reports_frames_pushed_off_when_full():
    ring = FrameRing(size=2)
    ring.put(frame(1), 0)
    assert ring.put(frame(3), 0).seq == 1   # slot 1 % 2 == 3 % 2


def test_lap_timer_learns_then_flags_slow_laps():
    timer = LapTimer(learn=5, factor=4, floor_ms=2)
    for _ in range(5):
        assert timer.record(1.0) is None
    assert timer.record(3.0) is None
    assert timer.record(10.0) is not None


def test_battery_shuts_down_at_reserve():
    battery = Battery(capacity_wh=10, load_w=10, reserve_pct=10)
    battery.drain(3600 * 0.85)
    assert not battery.must_shut_down
    battery.drain(3600 * 0.06)
    assert battery.must_shut_down
    battery.swap()
    assert battery.pct == 100 and not battery.must_shut_down


def test_default_pack_beats_the_eight_hour_benchmark():
    assert Battery().hours_left >= 8
