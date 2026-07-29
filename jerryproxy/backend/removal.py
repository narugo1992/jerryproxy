"""Crash-recoverable and alias-safe backend removal primitives."""

import os
import re
import stat
from pathlib import Path, PurePosixPath

from ..errors import CleanupScopeError, IntegrityError, RemovalCleanupError
from ..home import is_path_alias
from ..utils.fs import atomic_write_json, ensure_private_directory, read_json

_TRANSACTION_PATTERN = re.compile(r"^\.remove-[0-9a-f]{32}$")
_JOURNAL_NAME = "journal.json"
_MOVE_KINDS = {
    "download": ("downloads", "download-"),
    "installed": ("backends", "installed-"),
    "active-link": ("bin", "active-link"),
    "active-manifest": ("active", "active-manifest"),
}


def _alias_error(error_type, path):
    raise error_type(
        "refusing removal through managed symlink or Windows path alias (managed path alias): %s" % path
    )


def _validate_chain(root, target, error_type):
    root = Path(root)
    current = Path(target)
    while True:
        if is_path_alias(current):
            _alias_error(error_type, current)
        if current == root:
            return
        if current.parent == current:  # pragma: no cover - callers constrain targets below managed roots
            raise error_type("managed removal target escapes its area: %s" % target)
        current = current.parent


def _identity(stat_result):
    return (
        int(stat_result.st_dev),
        int(stat_result.st_ino),
        int(stat.S_IFMT(stat_result.st_mode)),
    )


def _lstat(path):
    try:
        return path.lstat()
    except FileNotFoundError:
        # Cleanup is idempotent when a selected path has already disappeared.
        return None


def _validate_removal_tree(root, target, error_type=CleanupScopeError, allowed_symlinks=()):
    # type: (Path, Path, type, tuple) -> None
    """Validate a complete removal tree without following path aliases."""

    root = Path(root)
    target = Path(target)
    allowed = set(Path(path) for path in allowed_symlinks)
    if target in allowed and target.is_symlink():
        _validate_chain(root, target.parent, error_type)
        return
    _validate_chain(root, target, error_type)
    status = _lstat(target)
    if status is None:
        return
    if is_path_alias(target):
        _alias_error(error_type, target)
    if not stat.S_ISDIR(status.st_mode):
        return
    entries = list(target.iterdir())
    _validate_chain(root, target, error_type)
    current = _lstat(target)
    if current is None or _identity(current) != _identity(status):
        raise error_type("managed removal directory changed during validation: %s" % target)
    for child in entries:
        _validate_removal_tree(root, child, error_type, tuple(allowed))


def _secure_path_size(root, target, error_type=CleanupScopeError):
    # type: (Path, Path, type) -> int
    """Measure a managed tree without following aliases."""

    root = Path(root)
    target = Path(target)
    _validate_chain(root, target, error_type)
    status = _lstat(target)
    if status is None:
        return 0
    if is_path_alias(target):
        _alias_error(error_type, target)
    if not stat.S_ISDIR(status.st_mode):
        return status.st_size
    entries = list(target.iterdir())
    _validate_chain(root, target, error_type)
    current = _lstat(target)
    if current is None or _identity(current) != _identity(status):
        raise error_type("managed removal directory changed during measurement: %s" % target)
    return sum(_secure_path_size(root, child, error_type) for child in entries)


def _remove_validated_tree(root, target, error_type, allowed):
    if target in allowed and target.is_symlink():
        _validate_chain(root, target.parent, error_type)
        target.unlink()
        return True
    _validate_chain(root, target, error_type)
    status = _lstat(target)
    if status is None:
        return False
    if is_path_alias(target):
        _alias_error(error_type, target)
    if not stat.S_ISDIR(status.st_mode):
        current = _lstat(target)
        if current is None:
            return False
        if _identity(current) != _identity(status) or is_path_alias(target):
            raise error_type("managed removal path changed before deletion: %s" % target)
        target.unlink()
        return True
    entries = list(target.iterdir())
    _validate_chain(root, target, error_type)
    current = _lstat(target)
    if current is None or _identity(current) != _identity(status) or is_path_alias(target):
        raise error_type("managed removal directory changed before deletion: %s" % target)
    for child in entries:
        _remove_validated_tree(root, child, error_type, allowed)
    _validate_chain(root, target, error_type)
    current = _lstat(target)
    if current is None:
        return True
    if _identity(current) != _identity(status) or is_path_alias(target):
        raise error_type("managed removal directory changed before final deletion: %s" % target)
    target.rmdir()
    return True


def _secure_remove_tree(root, target, error_type=CleanupScopeError, allowed_symlinks=()):
    # type: (Path, Path, type, tuple) -> bool
    """Delete a validated managed tree without traversing path aliases."""

    allowed = set(Path(path) for path in allowed_symlinks)
    _validate_removal_tree(root, target, error_type, tuple(allowed))
    return _remove_validated_tree(Path(root), Path(target), error_type, allowed)


def _removal_move(paths, source, destination, kind):
    # type: (JerryProxyPaths, Path, Path, str) -> dict
    """Create one journal move record from an existing managed source."""

    source = Path(source)
    destination = Path(destination)
    status = source.lstat()
    source_relative = source.relative_to(paths.root)
    destination_relative = destination.relative_to(paths.root)
    return {
        "kind": kind,
        "source": str(PurePosixPath(*source_relative.parts)),
        "destination": str(PurePosixPath(*destination_relative.parts)),
        "device": int(status.st_dev),
        "inode": int(status.st_ino),
        "mode": int(stat.S_IFMT(status.st_mode)),
    }


def _write_removal_journal(transaction, moves, phase="staging"):
    # type: (Path, list, str) -> None
    """Persist the recovery record before or after public-state moves."""

    atomic_write_json(Path(transaction) / _JOURNAL_NAME, {"phase": phase, "moves": moves})


def _relative_path(paths, value):
    if not isinstance(value, str) or not value or "\\" in value:
        raise IntegrityError("invalid removal journal path")
    relative = PurePosixPath(value)
    if relative.is_absolute() or any(part in ("", ".", "..") for part in relative.parts):
        raise IntegrityError("invalid removal journal path: %s" % value)
    return paths.root.joinpath(*relative.parts), relative.parts


def _load_removal_journal(paths, transaction):
    journal = transaction / _JOURNAL_NAME
    if is_path_alias(journal):
        _alias_error(IntegrityError, journal)
    try:
        value = read_json(journal)
    except ValueError as error:
        # Invalid JSON or a non-object journal cannot define recovery actions.
        raise IntegrityError("invalid removal transaction journal: %s" % journal) from error
    if set(value) != {"phase", "moves"} or value.get("phase") not in ("staging", "committed"):
        raise IntegrityError("invalid removal transaction journal: %s" % journal)
    raw_moves = value.get("moves")
    if not isinstance(raw_moves, list) or not raw_moves:
        raise IntegrityError("invalid removal transaction moves: %s" % journal)
    moves = []
    sources = set()
    destinations = set()
    for raw_move in raw_moves:
        if not isinstance(raw_move, dict) or set(raw_move) != {
            "kind",
            "source",
            "destination",
            "device",
            "inode",
            "mode",
        }:
            raise IntegrityError("invalid removal transaction move: %s" % journal)
        kind = raw_move.get("kind")
        if kind not in _MOVE_KINDS:
            raise IntegrityError("invalid removal transaction move kind: %s" % journal)
        source, source_parts = _relative_path(paths, raw_move.get("source"))
        destination, destination_parts = _relative_path(paths, raw_move.get("destination"))
        source_area, destination_name = _MOVE_KINDS[kind]
        valid_source = source_parts and source_parts[0] == source_area
        if kind == "download":
            valid_source = valid_source and len(source_parts) in (2, 3)
        elif kind == "installed":
            valid_source = valid_source and len(source_parts) == 3
        elif kind == "active-link":
            valid_source = valid_source and len(source_parts) == 2
        else:
            valid_source = valid_source and len(source_parts) == 2 and source_parts[-1].endswith(".json")
        if not valid_source:
            raise IntegrityError("invalid removal transaction source: %s" % source)
        if len(destination_parts) != 3 or destination_parts[:2] != (
            paths.runtimes.name,
            transaction.name,
        ):
            raise IntegrityError("invalid removal transaction destination: %s" % destination)
        if destination_name.endswith("-"):
            suffix = destination_parts[-1][len(destination_name) :]
            if not destination_parts[-1].startswith(destination_name) or not suffix.isdigit():
                raise IntegrityError("invalid removal transaction destination: %s" % destination)
        elif destination_parts[-1] != destination_name:
            raise IntegrityError("invalid removal transaction destination: %s" % destination)
        identity = (raw_move.get("device"), raw_move.get("inode"), raw_move.get("mode"))
        if any(not isinstance(item, int) or isinstance(item, bool) or item < 0 for item in identity):
            raise IntegrityError("invalid removal transaction identity: %s" % journal)
        if source in sources or destination in destinations:
            raise IntegrityError("duplicate removal transaction path: %s" % journal)
        sources.add(source)
        destinations.add(destination)
        moves.append(
            {
                "kind": kind,
                "source": source,
                "destination": destination,
                "identity": identity,
            }
        )
    return value["phase"], moves


def _validate_staged_move(paths, transaction, move, error_type):
    # type: (JerryProxyPaths, Path, dict, type) -> None
    """Verify that one rename moved the exact object recorded in the journal."""

    destination = Path(transaction) / Path(move["destination"]).name
    _validate_chain(paths.runtimes, destination.parent, error_type)
    status = destination.lstat()
    expected = (move["device"], move["inode"], move["mode"])
    if _identity(status) != expected:
        raise error_type("managed removal source changed during staging: %s" % move["source"])
    allowed = (destination,) if move["kind"] == "active-link" and destination.is_symlink() else ()
    _validate_removal_tree(paths.runtimes, destination, error_type, allowed)


def _restore_moves(paths, transaction, moves, replace):
    for move in reversed(moves):
        source = move["source"]
        destination = move["destination"]
        source_exists = os.path.lexists(str(source))
        destination_exists = os.path.lexists(str(destination))
        if source_exists and destination_exists:
            raise IntegrityError("ambiguous removal recovery paths: %s and %s" % (source, destination))
        if not destination_exists:
            continue
        _validate_chain(paths.runtimes, destination.parent, IntegrityError)
        status = destination.lstat()
        if _identity(status) != move["identity"]:
            raise IntegrityError("removal transaction payload identity changed: %s" % destination)
        current = source.parent
        while current != paths.root:
            if is_path_alias(current):
                _alias_error(IntegrityError, current)
            current = current.parent
        if not source.parent.exists():
            source_area = getattr(paths, source.relative_to(paths.root).parts[0])
            _validate_chain(source_area, source.parent, IntegrityError)
            ensure_private_directory(source.parent)
            _validate_chain(source_area, source.parent, IntegrityError)
        replace(str(destination), str(source))
        restored = source.lstat()
        if _identity(restored) != _identity(status):
            raise IntegrityError("removal rollback restored a different filesystem object: %s" % source)


def _rollback_removal_transaction(paths, transaction, raw_moves, replace=os.replace):
    # type: (JerryProxyPaths, Path, list, Callable) -> None
    """Restore already staged moves and retain evidence if restoration fails."""

    phase, moves = _load_removal_journal(paths, Path(transaction))
    if phase != "staging":  # pragma: no cover - manager calls rollback only before commit
        raise IntegrityError("cannot roll back a committed removal transaction: %s" % transaction)
    moved_destinations = set(
        paths.root.joinpath(*PurePosixPath(move["destination"]).parts) for move in raw_moves
    )
    selected = [move for move in moves if move["destination"] in moved_destinations]
    _restore_moves(paths, Path(transaction), selected, replace)


def _dispose_transaction(paths, transaction, moves):
    _validate_chain(paths.runtimes, transaction, IntegrityError)
    expected = set([transaction / _JOURNAL_NAME])
    expected.update(move["destination"] for move in moves)
    entries = set(transaction.iterdir())
    journal_temporaries = set(
        path for path in entries if path.name.startswith(".%s." % _JOURNAL_NAME)
    )
    expected.update(journal_temporaries)
    unexpected = entries.difference(expected)
    if unexpected:
        raise IntegrityError(
            "unexpected removal transaction content: %s" % sorted(str(path) for path in unexpected)[0]
        )
    for move in moves:
        destination = move["destination"]
        allowed = ()
        if move["kind"] == "active-link" and destination.is_symlink():
            allowed = (destination,)
        _secure_remove_tree(paths.runtimes, destination, IntegrityError, allowed)
    for temporary in journal_temporaries:
        _secure_remove_tree(paths.runtimes, temporary, IntegrityError)
    journal = transaction / _JOURNAL_NAME
    if os.path.lexists(str(journal)):
        if is_path_alias(journal):
            _alias_error(IntegrityError, journal)
        journal.unlink()
    transaction.rmdir()


def _dispose_removal_transaction(paths, transaction):
    # type: (JerryProxyPaths, Path) -> None
    """Finish physical deletion for a committed transaction."""

    phase, moves = _load_removal_journal(paths, Path(transaction))
    if phase != "committed":  # pragma: no cover - manager calls disposal only after commit
        raise IntegrityError("cannot dispose a staging removal transaction: %s" % transaction)
    _dispose_transaction(paths, Path(transaction), moves)


def _discard_rolled_back_transaction(paths, transaction):
    # type: (JerryProxyPaths, Path) -> None
    """Delete an empty staging transaction after successful rollback."""

    phase, moves = _load_removal_journal(paths, Path(transaction))
    if phase != "staging":  # pragma: no cover - rollback preserves the staging phase
        raise IntegrityError("cannot discard a committed removal transaction: %s" % transaction)
    if any(  # pragma: no cover - successful rollback removes every selected destination
        os.path.lexists(str(move["destination"])) for move in moves
    ):
        raise IntegrityError("removal transaction still contains staged state: %s" % transaction)
    _dispose_transaction(paths, Path(transaction), moves)


def _recover_removal_transactions(paths):
    # type: (JerryProxyPaths) -> None
    """Recover every journaled removal while the home-wide lock is held."""

    for transaction in sorted(paths.runtimes.iterdir()):
        if not _TRANSACTION_PATTERN.match(transaction.name) or not transaction.is_dir():
            continue
        if is_path_alias(transaction):
            _alias_error(IntegrityError, transaction)
        journal = transaction / _JOURNAL_NAME
        if not os.path.lexists(str(journal)):
            continue
        if not journal.is_file():
            raise IntegrityError("removal transaction journal is not a regular file: %s" % journal)
        phase, moves = _load_removal_journal(paths, transaction)
        if phase == "staging":
            _restore_moves(paths, transaction, moves, os.replace)
            _discard_rolled_back_transaction(paths, transaction)
        else:
            if any(os.path.lexists(str(move["source"])) for move in moves):
                raise IntegrityError("committed removal source unexpectedly exists: %s" % transaction)
            try:
                _dispose_transaction(paths, transaction, moves)
            except OSError as error:
                # Permission and filesystem failures leave the committed journal retryable.
                raise RemovalCleanupError(
                    "backend removal committed but quarantine cleanup failed at %s" % transaction
                ) from error
