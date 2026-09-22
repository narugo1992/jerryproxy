"""Recovery ordering is credential-free and independent of wall-clock sleeps."""

import random

import pytest

from jerryproxy.runtime.recovery import RetryBackoff, RetrySchedule, parse_retry_chain


def test_closed_chain_returns_stages():
    assert parse_retry_chain("current:1,adaptive:3,random:all") == (
        ("current", 1), ("adaptive", 3), ("random", None),
    )
    assert parse_retry_chain("random:12") == (("random", 12),)


@pytest.mark.parametrize("value", [
    None, 12, "", "random", "random:0", "random:-1", "random:01",
    "random:1.5", "random:10001", "random:ALL", "random:１", "random:1 ",
    "random:1,", "random:all,random:1", "current:2", "current:all",
    "fixed:1", "current:1:1", "random:" + "9" * 10000,
])
def test_closed_chain_rejects_ambiguous_or_unbounded_input(value):
    with pytest.raises(ValueError, match="retry chain"):
        parse_retry_chain(value)


def test_disabled_and_fixed_never_select_alternates():
    disabled = RetrySchedule("none", "a", rng=random.Random(4))
    disabled.update(("a", "b"))
    assert disabled.next("a", 0) is None
    fixed = RetrySchedule("fixed", "a", rng=random.Random(4))
    fixed.update(("a", "b"))
    assert fixed.next("b", 0) == "a"
    fixed.record("a", False, 0)
    assert fixed.next("b", 0) is None
    fixed.begin_sweep()
    assert fixed.next("b", 5) == "a"
    fixed.update(("b",))
    assert fixed.next("b", 100) is None


def test_random_sweep_survives_round_boundaries_and_unchanged_refresh():
    schedule = RetrySchedule("random", "0", rng=random.Random(7))
    nodes = tuple(str(index) for index in range(500))
    schedule.update(nodes)
    visited = []
    for _ in range(500):
        node = schedule.next("0", 0)
        visited.append(node)
        schedule.update(nodes)
    assert len(set(visited)) == 500
    assert visited != list(nodes)
    assert schedule.next("0", 0) is None
    schedule.begin_sweep()
    assert schedule.next("0", 0) in nodes


def test_fallback_deduplicates_and_finishes_all_candidates():
    schedule = RetrySchedule("fallback", "a", rng=random.Random(8))
    schedule.update(tuple("abcdef"))
    nodes = [schedule.next("a", 0) for _ in range(6)]
    assert nodes[0] == "a"
    assert set(nodes) == set("abcdef")
    assert schedule.next("a", 0) is None


def test_refresh_removes_statistics_and_pending_nodes_without_repeating_survivors():
    schedule = RetrySchedule("random", "a", rng=random.Random(5))
    schedule.update(tuple("abc"))
    first = schedule.next("a", 0)
    schedule.record(first, False, 0)
    schedule.update((first, "new"))
    assert schedule.next(first, 0) == "new"
    assert schedule.next(first, 0) is None
    schedule.update(("new",))
    assert first not in schedule.statistics
    assert len(schedule.statistics) <= 1


def test_cooling_candidates_are_retained_until_eligible():
    schedule = RetrySchedule("random", "a", rng=random.Random(0))
    schedule.update(("a",))
    schedule.record("a", False, 10)
    assert schedule.next("a", 14) is None
    assert schedule.next("a", 15) == "a"
    schedule.record("a", True, 16)
    schedule.begin_sweep()
    assert schedule.next("a", 16) == "a"


def test_adaptive_exploits_success_but_explores_and_never_starves():
    schedule = RetrySchedule("adaptive", "a", rng=random.Random(0))
    schedule.update(tuple("abc"))
    schedule.record("b", True, 0)
    schedule.record("a", False, 0)
    assert schedule.next("a", 10) == "b"
    assert {schedule.next("a", 10), schedule.next("a", 10)} == {"a", "c"}
    assert schedule.next("a", 10) is None
    # Seed 31 starts below epsilon=.1, forcing recovery-only exploration.
    exploring = RetrySchedule("adaptive", "a", rng=random.Random(31))
    exploring.update(tuple("abc"))
    exploring.record("b", True, 0)
    assert exploring.next("a", 10) == "a"


def test_invalid_policy_and_chain_combination_are_rejected():
    with pytest.raises(ValueError, match="retry policy"):
        RetrySchedule("unknown", "a")
    with pytest.raises(ValueError, match="fallback"):
        RetrySchedule("fixed", "a", chain="random:all")


def test_removed_attempt_result_does_not_reintroduce_statistics():
    schedule = RetrySchedule("random", "a")
    schedule.update(("b",))
    schedule.record("a", False, 0)
    assert schedule.statistics == {}


def test_cooldown_is_bounded_and_reports_earliest_unvisited_candidate():
    schedule = RetrySchedule("random", "a", rng=random.Random(2))
    schedule.update(("a", "b"))
    assert schedule.wait_seconds(0) == 0
    schedule.record("a", False, 0)
    schedule.record("b", False, 2)
    assert schedule.wait_seconds(3) == 2
    assert schedule.next("a", 5) == "a"
    assert schedule.wait_seconds(5) == 2
    assert schedule.next("a", 7) == "b"
    assert schedule.wait_seconds(7) == 0
    for _ in range(1000):
        schedule.record("a", False, 10)
    schedule.update(("a",))
    schedule.begin_sweep()
    assert schedule.wait_seconds(10) == 60
    assert schedule.next("a", 69) is None
    assert schedule.next("a", 70) == "a"


def test_fixed_wait_ignores_available_alternates():
    schedule = RetrySchedule("fixed", "a")
    schedule.update(("a", "b"))
    schedule.record("a", False, 0)
    assert schedule.wait_seconds(0) == 5


def test_capped_backoff_and_stable_period_reset():
    timing = RetryBackoff(rng=random.Random(7))
    delays = [timing.failed(0) for _ in range(1000)]
    assert 4 <= delays[0] <= 6
    assert 8 <= delays[1] <= 12
    assert all(0 < delay <= 60 for delay in delays)
    timing.healthy(10)
    timing.healthy(11)
    # A brief recovery must not restart the exponential sequence.
    assert timing.failed(12) >= 48
    timing.healthy(20)
    timing.healthy(79)
    assert timing.failed(79) >= 48
    timing.healthy(100)
    timing.healthy(160)
    assert 4 <= timing.failed(161) <= 6


def test_backoff_reset_can_be_observed_at_next_failure():
    timing = RetryBackoff(rng=random.Random(3))
    timing.failed(0)
    timing.failed(1)
    timing.healthy(10)
    assert 4 <= timing.failed(70) <= 6
