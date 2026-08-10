"""Resolve the exact proxy release this lane builds from.

The repository catalog already records the official asset name, URL, and a
SHA-256 that GitHub itself issued.  Reading it here means the harness trusts the
same release evidence the product does, instead of introducing a second pin that
could drift from it.
"""

import argparse
import sys

from jerryproxy.data import read_backend_catalog_json

FIELDS = ("version", "asset", "sha256", "url", "executable", "archive_format")

# Fixture images are Alpine, so a backend that ships separate glibc and musl
# builds must take the musl one. Naming the key per backend keeps that choice
# visible instead of hiding it behind a substring match.
PLATFORM_KEYS = {
    "xray": "linux-amd64",
    "sing-box": "linux-amd64-musl",
}
BACKENDS = tuple(sorted(PLATFORM_KEYS))


def resolve(backend="xray", platform=None):  # type: (str, str) -> dict
    """Return the newest catalog release and its verified platform artifact."""

    if platform is None:
        platform = PLATFORM_KEYS.get(backend)
        if platform is None:
            raise SystemExit("no fixture platform key is recorded for %s" % backend)
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
        "executable": artifact["executable"],
        "archive_format": artifact["archive_format"],
    }


def main():  # type: () -> int
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend", default="xray", choices=BACKENDS)
    parser.add_argument("--field", choices=FIELDS, required=True)
    arguments = parser.parse_args()
    sys.stdout.write("%s\n" % resolve(arguments.backend)[arguments.field])
    return 0


if __name__ == "__main__":
    sys.exit(main())
