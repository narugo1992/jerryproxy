"""Licence gate for everything JerryProxy distributes.

JerryProxy is Apache-2.0, but a wheel drags its dependency chain along and a
PyInstaller executable embeds that chain outright. A dependency added without a
licence review is therefore a distribution defect, not a packaging detail, and
this gate exists to make that defect fail a build rather than reach a release.

``tools/licenses.json`` is the reviewed record and the single source of truth.
``THIRD_PARTY_LICENSES.md`` is generated from it and checked in, so the readable
file cannot drift from the reviewed one.

The gate enforces four invariants:

1. every distribution in the installed runtime closure has a reviewed record;
2. every recorded licence is on the reviewed allowlist;
3. the recorded licence still matches what the installed distribution declares,
   so a licence change between versions is caught rather than assumed away;
4. the generated document matches the record.

Run ``python -m tools.licenses`` to check and ``--write`` to regenerate the
document. Nothing here contacts a network.
"""

import argparse
import io
import json
import os
import re
import sys

try:  # Python 3.8+
    import importlib.metadata as metadata
except ImportError:  # pragma: no cover - the 3.7 maintainer path
    import importlib_metadata as metadata

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
RECORD = os.path.join(HERE, "licenses.json")
DOCUMENT = os.path.join(ROOT, "THIRD_PARTY_LICENSES.md")
REQUIREMENTS = os.path.join(ROOT, "requirements.txt")

# Only the distributions that are actually conveyed. Test, docs, and developer
# tooling never leaves the repository, so reviewing it would dilute the gate
# with findings that carry no obligation.
#
# Two build components are exceptions, and they are named rather than walked:
# PyInstaller contributes the bootloader that is linked into every frozen
# executable, and hooks-contrib contributes runtime hooks that are embedded with
# it. Their own dependency trees -- altgraph, macholib, pefile, setuptools and
# the rest -- run during analysis and never enter the executable, so walking
# from PyInstaller would demand a review of components nobody receives.
CONVEYED_BUILD_LEAVES = ("pyinstaller", "pyinstaller-hooks-contrib")

# What a declared licence may look like once normalised. Metadata is famously
# inconsistent — some distributions use the `License` field, some only a
# classifier, some a modern SPDX expression — so each recorded licence lists the
# spellings that count as agreement rather than demanding one canonical string.
EQUIVALENT_SPELLINGS = {
    "Apache-2.0": ("apache-2.0", "apache 2.0", "apache software license", "apache license 2.0"),
    "BSD-2-Clause": ("bsd-2-clause", "bsd license", "bsd"),
    "BSD-3-Clause": ("bsd-3-clause", "bsd license", "bsd"),
    "MIT": ("mit", "mit license", "mit-license"),
    "MPL-2.0": ("mpl-2.0", "mozilla public license 2.0 (mpl 2.0)", "mpl 2.0"),
    "MPL-2.0 AND MIT": ("mpl-2.0 and mit", "mpl-2.0", "mplv2.0, mit licences", "mit"),
    "PSF-2.0": ("psf-2.0", "python software foundation license"),
    "Unlicense": ("unlicense", "the unlicense (unlicense)"),
    "GPL-2.0-or-later WITH Bootloader-exception": (
        "gpl-2.0-or-later with bootloader-exception",
        "gnu general public license v2 (gplv2)",
        "gplv2-or-later with a special exception which allows to use pyinstaller",
    ),
    "Apache-2.0 AND GPL-2.0-or-later WITH Bootloader-exception": (
        "apache-2.0 and gpl-2.0-or-later with bootloader-exception",
        "apache software license",
        "gnu general public license v2 (gplv2)",
    ),
}


def _load_record():  # type: () -> dict
    with io.open(RECORD, encoding="utf-8") as stream:
        return json.load(stream)


def _canonical(name):  # type: (str) -> str
    return re.sub(r"[-_.]+", "-", name).lower()


def _declared_names(path):  # type: (str) -> list
    """Read the direct requirement names out of a requirements file."""

    names = []
    with io.open(path, encoding="utf-8") as stream:
        for line in stream:
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            found = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)", line)
            if found:
                names.append(found.group(1))
    return names


def _closure(roots):  # type: (list) -> dict
    """Walk installed metadata from the direct requirements outwards.

    Optional extras are excluded because JerryProxy does not request them, but
    environment markers are otherwise kept: a dependency that only appears on
    one interpreter or one operating system is still conveyed there.
    """

    resolved = {}
    pending = list(roots)
    while pending:
        name = pending.pop()
        key = _canonical(name)
        if key in resolved:
            continue
        try:
            distribution = metadata.distribution(name)
        except metadata.PackageNotFoundError:
            # Not installed in this environment. The record still has to cover
            # it, and the record still has to cover it, so the closure keeps the
            # name with no metadata to confirm against.
            resolved[key] = None
            continue
        resolved[key] = distribution
        for requirement in distribution.requires or []:
            head, _, marker = requirement.partition(";")
            if "extra" in marker:
                continue
            dependency = re.split(r"[<>=!~\[(;\s]", head.strip(), 1)[0].strip()
            if dependency:
                pending.append(dependency)
    return resolved


def _declared_licenses(distribution):  # type: (object) -> list
    """Every licence spelling this installed distribution offers."""

    spellings = []
    for field in ("License-Expression", "License"):
        value = distribution.metadata.get(field)
        if value and value.strip() and "\n" not in value.strip():
            spellings.append(value.strip())
    for classifier in distribution.metadata.get_all("Classifier") or []:
        if classifier.startswith("License ::"):
            spellings.append(classifier.split("::")[-1].strip())
    return spellings


def _recorded_licenses(item):  # type: (dict) -> list
    """Every licence this record accepts, primary first.

    A component can be conveyed under more than one licence when the version
    selected differs by interpreter and upstream relicensed in between.
    """

    return [item["license"]] + [other["license"] for other in item.get("varies", [])]


def _agrees(item, spellings):  # type: (dict, list) -> bool
    accepted = set()
    for recorded in _recorded_licenses(item):
        accepted.update(EQUIVALENT_SPELLINGS.get(recorded, ()))
        accepted.add(recorded.lower())
    return any(spelling.lower() in accepted for spelling in spellings)


def _check(record):  # type: (dict) -> tuple
    failures = []
    confirmed = set()
    recorded = {_canonical(item["name"]): item for item in record["components"]}
    allowed = set(record["allowed"])

    for name, item in sorted(recorded.items()):
        for value in _recorded_licenses(item):
            if value not in allowed:
                failures.append(
                    "%s is recorded as %s, which is not on the reviewed allowlist"
                    % (name, value)
                )

    closure = _closure(_declared_names(REQUIREMENTS))
    for name in CONVEYED_BUILD_LEAVES:
        try:
            closure.setdefault(_canonical(name), metadata.distribution(name))
        except metadata.PackageNotFoundError:
            closure.setdefault(_canonical(name), None)
    for name in sorted(closure):
        if name not in recorded:
            failures.append(
                "%s is conveyed but has no licence record; review it and add it to "
                "tools/licenses.json" % name
            )
    for name in sorted(recorded):
        # A record marked conditional covers a component that only some
        # interpreters or platforms pull in, so its absence here proves nothing.
        # The asymmetry is deliberate: an unrecorded component always fails,
        # while a possibly-stale record does not, because the first is a
        # distribution defect and the second is only untidiness.
        if name not in closure and not recorded[name].get("conditional"):
            failures.append(
                "%s has a licence record but is no longer conveyed; remove the stale "
                "record from tools/licenses.json" % name
            )

    for name, distribution in sorted(closure.items()):
        item = recorded.get(name)
        if item is None or distribution is None:
            continue
        spellings = _declared_licenses(distribution)
        if not spellings:
            failures.append(
                "%s declares no licence in its installed metadata, so the record "
                "cannot be confirmed" % name
            )
        elif _agrees(item, spellings):
            confirmed.add(name)
        else:
            failures.append(
                "%s is recorded as %s but the installed %s declares %s; re-review it"
                % (
                    name,
                    " / ".join(_recorded_licenses(item)),
                    distribution.version,
                    "/".join(spellings),
                )
            )
    return failures, confirmed


def _render(record):  # type: (dict) -> str
    lines = [
        "# Third-party licences",
        "",
        "<!-- Generated by `make license_check WRITE=1`. Edit tools/licenses.json instead. -->",
        "",
        record["project"]["notice"],
        "",
        "## Conveyed Python distributions",
        "",
        "`wheel` means the component is reached through the published wheel's",
        "dependency chain. `standalone` means it is embedded in the PyInstaller",
        "executables, where there is no dependency resolution to defer to.",
        "",
        "| Component | Licence | Reaches | Obligation |",
        "| --- | --- | --- | --- |",
    ]
    for item in record["components"]:
        lines.append(
            "| %s | %s | %s | %s |"
            % (
                item["name"],
                " or ".join(_recorded_licenses(item)),
                ", ".join(item["distribution"]),
                item["obligation"],
            )
        )
    notes = [item for item in record["components"] if item.get("note")]
    if notes:
        lines += ["", "### Notes", ""]
        lines += ["- **%s** — %s" % (item["name"], item["note"]) for item in notes]

    lines += ["", "## Backend binaries", "", record["backends"]["note"], ""]
    lines += ["| Backend | Upstream | Licence |", "| --- | --- | --- |"]
    for item in record["backends"]["components"]:
        lines.append("| %s | %s | %s |" % (item["name"], item["repository"], item["license"]))
    backend_notes = [item for item in record["backends"]["components"] if item.get("note")]
    if backend_notes:
        lines += ["", "### Notes", ""]
        lines += ["- **%s** — %s" % (item["name"], item["note"]) for item in backend_notes]
    lines += ["", "## Reviewed allowlist", ""]
    lines += ["- `%s`" % value for value in record["allowed"]]
    lines.append("")
    return "\n".join(lines)


def main():  # type: () -> int
    parser = argparse.ArgumentParser(description="Check the distributed licence record.")
    parser.add_argument(
        "--write", action="store_true", help="regenerate THIRD_PARTY_LICENSES.md"
    )
    arguments = parser.parse_args()

    record = _load_record()
    rendered = _render(record)
    if arguments.write:
        with io.open(DOCUMENT, "w", encoding="utf-8") as stream:
            stream.write(rendered)
        sys.stdout.write("wrote %s\n" % os.path.relpath(DOCUMENT, ROOT))
        return 0

    failures, confirmed = _check(record)
    try:
        with io.open(DOCUMENT, encoding="utf-8") as stream:
            current = stream.read()
    except IOError:
        current = None
    if current != rendered:
        failures.append(
            "THIRD_PARTY_LICENSES.md does not match tools/licenses.json; "
            "run `make license_check WRITE=1`"
        )

    for failure in failures:
        sys.stdout.write("FAIL %s\n" % failure)
    if failures:
        return 1
    # Say what was actually confirmed against installed metadata rather than
    # implying the whole record was re-verified: a component that this
    # environment does not install can only be reported as recorded.
    total = len(record["components"])
    sys.stdout.write(
        "OK   %d conveyed distributions recorded, %d confirmed against installed "
        "metadata here (%d not installed in this environment); %d backend licences "
        "recorded\n"
        % (
            total,
            len(confirmed),
            total - len(confirmed),
            len(record["backends"]["components"]),
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
