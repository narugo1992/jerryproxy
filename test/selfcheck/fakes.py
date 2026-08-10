"""Deterministic Requests boundary doubles for self-check tests."""

import hashlib
from types import SimpleNamespace

from jerryproxy.selfcheck import relay as selfcheck_module


def relay_payload():
    """Return one deterministic exact-size relay probe body."""

    seed = b"jerryproxy relay self-check fixture\n"
    return (seed * ((selfcheck_module.RELAY_PROBE_BYTES // len(seed)) + 1))[
        : selfcheck_module.RELAY_PROBE_BYTES
    ]


class FakeRelayResponse(object):
    """Minimal streamed response with observable bounded reads."""

    def __init__(
        self,
        payload,
        status_code=206,
        content_range=None,
        final_url="https://relay.example/result?private=signed-value",
        history=None,
        chunks=None,
    ):
        self.payload = payload
        self.status_code = status_code
        self.headers = {
            "Content-Range": content_range
            or "bytes 0-%d/%d"
            % (selfcheck_module.RELAY_PROBE_BYTES - 1, selfcheck_module.RELAY_PROBE_SIZE)
        }
        self.url = final_url
        self.history = history if history is not None else [SimpleNamespace(url="https://relay.example/start")]
        self.closed = False
        self.iterated_bytes = 0
        self.chunks = chunks

    def iter_content(self, chunk_size):
        if self.chunks is not None:
            for block in self.chunks:
                self.iterated_bytes += len(block)
                yield block
            return
        for offset in range(0, len(self.payload), chunk_size):
            block = self.payload[offset : offset + chunk_size]
            self.iterated_bytes += len(block)
            yield block

    def close(self):
        self.closed = True


class FakeRelaySession(object):
    """Minimal session returning one response or Requests exception."""

    def __init__(self, outcome):
        self.outcome = outcome
        self.calls = []
        self.closed = False
        self.max_redirects = None

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        if isinstance(self.outcome, BaseException):
            raise self.outcome
        return self.outcome

    def close(self):
        self.closed = True


class RelaySessionFactory(object):
    """Create observable sessions from a response factory."""

    def __init__(self, outcome_factory):
        self.outcome_factory = outcome_factory
        self.sessions = []

    def __call__(self):
        session = FakeRelaySession(self.outcome_factory())
        self.sessions.append(session)
        return session


def verified_relay_session_factory(monkeypatch):
    """Return a factory whose response matches a test-scoped digest."""

    payload = relay_payload()
    monkeypatch.setattr(
        selfcheck_module,
        "RELAY_PROBE_SHA256",
        hashlib.sha256(payload).hexdigest(),
    )
    return RelaySessionFactory(lambda: FakeRelayResponse(payload))


SELFCHECK_MODULES = (
    "backend",
    "dependencies",
    "environment",
    "fixtures",
    "processes",
    "recovery",
    "relay",
    "resources",
    "result",
    "runner",
    "runtime",
    "subscription",
)


def patch_across_selfcheck(monkeypatch, name, value):
    """Replace ``name`` in every self-check module that binds it.

    Each module imports the helpers it uses by name, so it holds its own
    binding. A host-wide condition such as an unsupported platform is only
    simulated faithfully when every consumer sees the replacement.

    Raises if the name is bound nowhere, so a rename cannot silently turn the
    caller into a test that patches nothing and asserts against real behaviour.
    """

    import importlib

    patched = []
    for suffix in SELFCHECK_MODULES:
        module = importlib.import_module("jerryproxy.selfcheck." + suffix)
        if hasattr(module, name):
            monkeypatch.setattr(module, name, value)
            patched.append(suffix)
    if not patched:
        raise AssertionError("no self-check module binds %r" % name)
    return tuple(patched)
