"""Credential-free, session-local ordering for outage recovery."""

import random
import re

DEFAULT_RETRY_CHAIN = "current:1,adaptive:3,random:all"
RETRY_POLICIES = ("none", "fixed", "random", "adaptive", "fallback")


def parse_retry_chain(value):
    """Validate the closed fallback grammar and return (stage, limit) pairs."""

    if not isinstance(value, str) or not 1 <= len(value) <= 128:
        raise ValueError("retry chain must be a bounded stage list")
    stages = []
    seen = set()
    for item in value.split(","):
        match = re.fullmatch(r"(current|adaptive|random):(all|[1-9][0-9]{0,4})", item)
        if match is None:
            raise ValueError("invalid retry chain stage")
        name, count = match.groups()
        limit = None if count == "all" else int(count)
        if name in seen or (limit is not None and limit > 10000) or (name == "current" and limit != 1):
            raise ValueError("duplicate or invalid retry chain limit")
        seen.add(name)
        stages.append((name, limit))
    return tuple(stages)


class RetrySchedule(object):
    """Choose IDs only when called during an outage, without owning I/O.

    A round deadline does not reset this object. Call ``begin_sweep`` only
    after the pool is exhausted and the supervisor has applied backoff.
    Statistics and pending work are limited to the authoritative node set.
    """

    def __init__(self, policy, initial, chain=None, rng=None):
        if policy not in RETRY_POLICIES:
            raise ValueError("unknown retry policy")
        if chain is not None and policy != "fallback":
            raise ValueError("retry chain requires fallback policy")
        self.policy = policy
        self.initial = initial
        self.rng = rng or random.Random()
        if policy == "fallback":
            self.stages = parse_retry_chain(DEFAULT_RETRY_CHAIN if chain is None else chain)
        elif policy == "none":
            self.stages = ()
        else:
            self.stages = ((policy, None),)
        self.nodes = ()
        self.statistics = {}
        self.begin_sweep()

    def begin_sweep(self):
        """Start another sweep without resetting learned health or cooldowns."""

        self.visited = set()
        self.counts = dict((stage, 0) for stage, _ in self.stages)

    def update(self, node_ids):
        """Replace the authoritative pool while preserving surviving progress."""

        nodes = tuple(dict.fromkeys(node_ids))
        self.nodes = nodes
        self.visited.intersection_update(nodes)
        self.statistics = {node: value for node, value in self.statistics.items() if node in nodes}

    def record(self, node, ok, now):
        """Record a completed attempt using a monotonic timestamp."""

        if node not in self.nodes:
            return
        estimate, _, failures, _ = self.statistics.get(node, (0.5, now, 0, 0.0))
        failures = 0 if ok else min(5, failures + 1)
        cooldown = 0.0 if ok else now + min(60.0, 5.0 * 2 ** (failures - 1))
        self.statistics[node] = (0.5 * estimate + 0.5 * bool(ok), now, failures, cooldown)

    def wait_seconds(self, now):
        """Return the earliest pending cooldown, or zero for a finished sweep.

        The supervisor still applies round backoff when this returns zero
        after ``next`` returns None; zero never requests a busy loop.
        """

        nodes = (self.initial,) if self.policy == "fixed" else self.nodes
        waits = [
            max(0.0, self.statistics.get(node, (0, 0, 0, 0))[3] - now)
            for node in nodes if node not in self.visited
        ]
        return min(waits, default=0.0)

    def next(self, current, now):
        """Return one eligible ID, or None when waiting/new sweep is needed."""

        eligible = [
            node for node in self.nodes
            if node not in self.visited and self.statistics.get(node, (0, 0, 0, 0))[3] <= now
        ]
        for stage, limit in self.stages:
            if limit is not None and self.counts[stage] >= limit:
                continue
            if stage in ("current", "fixed"):
                candidates = [self.initial if stage == "fixed" else current]
                candidates = [node for node in candidates if node in eligible]
            else:
                candidates = eligible
            if not candidates:
                continue
            if stage == "adaptive" and self.rng.random() >= 0.1:
                def score(node):
                    estimate, measured, _, _ = self.statistics.get(node, (0.5, now, 0, 0))
                    return 0.5 + (estimate - 0.5) * 0.5 ** (max(0.0, now - measured) / 300.0)

                node = max(candidates, key=score)
            else:
                node = self.rng.choice(candidates)
            self.visited.add(node)
            self.counts[stage] += 1
            return node
        return None


class RetryBackoff(object):
    """Bound recovery cadence without resetting it on a brief healthy blip."""

    def __init__(self, rng=None):
        self.rng = rng or random.Random()
        self.failures = 0
        self.healthy_since = None

    def healthy(self, now):
        """Observe health; sixty stable seconds reset the next retry delay."""

        if self.healthy_since is None:
            self.healthy_since = now
        if now - self.healthy_since >= 60.0:
            self.failures = 0

    def failed(self, now):
        """Return the actual jittered delay, capped after jitter is applied."""

        if self.healthy_since is not None and now - self.healthy_since >= 60.0:
            self.failures = 0
        self.healthy_since = None
        base = min(60.0, 5.0 * 2 ** self.failures)
        self.failures = min(4, self.failures + 1)
        return min(60.0, base * self.rng.uniform(0.8, 1.2))
