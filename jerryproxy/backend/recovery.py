"""Coordinate backend transaction recovery under the home-wide lock."""

from pathlib import PurePosixPath

from ..errors import IntegrityError
from .activation import _recover_use_operation, _scan_use_recovery, recover_use_record
from .installation import (
    _dispose_file,
    _recover_record,
    _scan_install_recovery,
    preflight_install_record,
)
from .platform import detect_platform
from .removal import (
    preflight_removal_record,
    preflight_removal_transactions,
    recover_removal_record,
)


def _record_sets(record):
    read_paths = getattr(record, "read_paths", getattr(record, "read_set", ()))
    write_paths = getattr(record, "write_paths", getattr(record, "write_set", ()))
    return frozenset(read_paths), frozenset(write_paths)


def _paths_intersect(first, second):
    first_parts = PurePosixPath(first).parts
    second_parts = PurePosixPath(second).parts
    shortest = min(len(first_parts), len(second_parts))
    return first_parts[:shortest] == second_parts[:shortest]


def _records_conflict(first, second):
    first_reads, first_writes = _record_sets(first)
    second_reads, second_writes = _record_sets(second)
    for first_path in first_reads | first_writes:
        for second_path in second_reads | second_writes:
            if first_path not in first_writes and second_path not in second_writes:
                continue
            if _paths_intersect(first_path, second_path):
                return True
    return False


def _preflight(paths, platform_info):
    install_records, install_orphans = _scan_install_recovery(paths)
    use_records, use_orphans = _scan_use_recovery(paths, platform_info)
    removal_records = preflight_removal_transactions(paths, platform_info)
    records = tuple(install_records) + tuple(use_records) + tuple(removal_records)
    for index, first in enumerate(records):
        for second in records[index + 1 :]:
            if _records_conflict(first, second):
                raise IntegrityError(
                    "conflicting backend recovery records: %s/%s and %s/%s"
                    % (first.kind, first.operation, second.kind, second.operation)
                )
    for record in records:
        if record.kind == "install":
            preflight_install_record(record)
        elif record.kind == "use":
            recover_use_record(paths, record)
        elif record.kind == "remove":
            preflight_removal_record(paths, record)
        else:
            raise IntegrityError("unknown backend recovery record kind: %s" % record.kind)
    return records, install_orphans, use_orphans


def recover_backend_transactions(paths, platform_info=None):
    # type: (JerryProxyPaths, Optional[PlatformInfo]) -> None
    """Recover every recognized backend transaction before normal operations."""

    selected_platform = platform_info or detect_platform()
    records, install_orphans, use_orphans = _preflight(paths, selected_platform)
    for record in sorted(records, key=lambda item: (item.operation, item.kind)):
        if record.kind == "install":
            _recover_record(record)
        elif record.kind == "use":
            _recover_use_operation(paths, selected_platform, record.operation)
        elif record.kind == "remove":
            recover_removal_record(paths, record, selected_platform)
        else:
            raise IntegrityError("unknown backend recovery record kind: %s" % record.kind)
    for temporary, identity in install_orphans:
        _dispose_file(paths, temporary, identity)
    for temporary, identity in use_orphans:
        from .removal import _secure_remove_tree

        _secure_remove_tree(
            paths.runtimes,
            temporary,
            IntegrityError,
            expected_identity=identity,
            private_names=True,
        )
