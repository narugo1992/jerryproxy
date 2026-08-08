"""Resolve the exact proxy release this lane builds from.

The repository catalog already records the official asset name, URL, and a
SHA-256 that GitHub itself issued.  Reading it here means the harness trusts the
same release evidence the product does, instead of introducing a second pin that
could drift from it.
"""

import argparse
import sys

from jerryproxy.data import read_backend_catalog_json

PLATFORM = "linux-amd64"
FIELDS = ("version", "asset", "sha256", "url")


def resolve(backend="xray", platform=PLATFORM):  # type: (str, str) -> dict
    """Return the newest catalog release and its verified platform artifact."""

    catalog = read_backend_catalog_json(backend)
    version = catalog["versions"][0]
    artifact = version["artifacts"][platform]
    digest = artifact.get("sha256")
    if not digest or len(digest) != 64:
        raise SystemExit("%s %s has no usable SHA-256 in the catalog" % (backend, platform))
    return {
        "version": version["version"],
        "asset": artifact["name"],
        "sha256": digest,
        "url": artifact["url"],
    }


def main():  # type: () -> int
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend", default="xray")
    parser.add_argument("--field", choices=FIELDS, required=True)
    arguments = parser.parse_args()
    sys.stdout.write("%s\n" % resolve(arguments.backend)[arguments.field])
    return 0


if __name__ == "__main__":
    sys.exit(main())
