import pytest

_END_TO_END_PACKAGE = "test/e2e/"


def pytest_collection_modifyitems(items):
    """Separate the deterministic unit matrix from the Docker-backed E2E lane.

    ``make unittest`` selects ``-m unittest`` and must stay deterministic and
    network-free, so tests under ``test/e2e`` are marked ``e2e`` instead. They
    are never collected into the unit matrix and never inflate unit coverage.
    """

    for item in items:
        if item.nodeid.startswith(_END_TO_END_PACKAGE):
            item.add_marker(pytest.mark.e2e)
        else:
            item.add_marker(pytest.mark.unittest)
