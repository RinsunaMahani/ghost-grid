from databox.vault import Guard, Version


class Clock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


def text_version(name):
    return Version(name, 1, "x", 2000, 4.5, 0.0, "id")


def test_new_files_never_count():
    guard = Guard(min_changes=1)
    assert guard.check("a", None, 7.9, 2000, 20) is None


def test_mass_change_trips_at_the_limit():
    guard = Guard(min_changes=5, change_ratio=0.3, entropy_jumps=99, clock=Clock())
    results = [guard.check(f"f{i}", text_version(f"f{i}"), 4.6, 2000, 20) for i in range(6)]
    assert results[:5] == [None] * 5      # limit is max(5, 30% of 20) = 6
    assert results[5].startswith("mass change")


def test_changes_outside_the_window_expire():
    clock = Clock()
    guard = Guard(window_s=10, min_changes=3, change_ratio=0, entropy_jumps=99, clock=clock)
    guard.check("a", text_version("a"), 4.6, 2000, 20)
    guard.check("b", text_version("b"), 4.6, 2000, 20)
    clock.t = 30
    assert guard.check("c", text_version("c"), 4.6, 2000, 20) is None


def test_encryption_pattern_trips():
    guard = Guard(entropy_jumps=3, min_changes=99, clock=Clock())
    assert guard.check("a", text_version("a"), 7.95, 2000, 20) is None
    assert guard.check("b", text_version("b"), 7.95, 2000, 20) is None
    assert guard.check("c", text_version("c"), 7.95, 2000, 20).startswith("encryption pattern")


def test_small_files_do_not_count_as_encrypted():
    guard = Guard(entropy_jumps=1, min_changes=99, clock=Clock())
    assert guard.check("a", text_version("a"), 7.95, 200, 20) is None
