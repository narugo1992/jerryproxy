

from jerryproxy.home import JerryProxyPaths
from jerryproxy.selfcheck import backend as selfcheck_module
from jerryproxy.selfcheck import build_checks


def test_backend_inventory_check_keeps_unexpected_internal_failures_as_errors(tmp_path, monkeypatch):
    class BrokenManager(object):
        def __init__(self, paths, platform_info=None):
            self.paths = paths
            self.platform_info = platform_info

        def inventory(self):
            raise RuntimeError("unexpected recovery failure")

    monkeypatch.setattr(selfcheck_module, "BackendManager", BrokenManager)

    result = dict(build_checks(JerryProxyPaths(tmp_path)))["backend inventory"]()

    assert result.level == "ERR"
    assert result.detail == "RuntimeError: unexpected recovery failure"
    assert result.diagnostics and "unexpected recovery failure" in result.diagnostics[0]
