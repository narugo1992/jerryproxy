"""Build a sed script that removes every generated value from captured logs.

The fixture servers emit access records, so a captured log can carry a password,
UUID, key, or short ID. Redaction that covers only the sentinel nonce would be
one value wide while the log surface is much wider.

The set is derived from two inputs, because the environment file alone is not
sufficient: the SS password and the VMess UUID appear there only inside base64
payloads, and the Reality private key is never exported at all. The generator
therefore also writes a private list of raw secrets, and both are unioned here.

Non-secret entries — service addresses, ports, backend identity — are kept so a
failure log stays readable.
"""

import argparse
import re
import sys

PUBLIC_PREFIXES = (
    "JERRYPROXY_E2E_SENTINEL_",
    "JERRYPROXY_E2E_BACKEND",
    "JERRYPROXY_E2E_PUBLIC_PROBES",
    "V2RAY_SUBSCRIPTION",
)
# Split a node URI on its structural separators and keep the long opaque runs:
# base64 userinfo, UUIDs, Reality keys, and short IDs. Treating the separators
# as part of a token would capture "pbk=KEY" or "//USERINFO", which then fails
# to match the bare value as it appears in a log.
_SEPARATOR = re.compile(r"[:/@?&#=,;]+")
_MINIMUM_TOKEN = 16


def _parse(path):  # type: (str) -> dict
    values = {}
    with open(path, "r", encoding="utf-8") as stream:
        for line in stream:
            name, separator, value = line.rstrip("\n").partition("=")
            if not separator:
                continue
            values[name] = value.strip("'")
    return values


def _sed_literal(value):  # type: (str) -> str
    """Escape a value for the left side of a sed s||| expression."""

    return re.sub(r"([|\\&.*\[\]^$])", r"\\\1", value)


def build(values):  # type: (dict) -> list
    """Return sed expressions, longest first so substrings cannot shadow."""

    secrets = set()
    for name, value in values.items():
        if not value or name.startswith(PUBLIC_PREFIXES):
            continue
        secrets.add(value)
        if name.endswith("_NODE"):
            secrets.update(
                part for part in _SEPARATOR.split(value) if len(part) >= _MINIMUM_TOKEN
            )
    return [
        "s|%s|[REDACTED]|g" % _sed_literal(secret)
        for secret in sorted(secrets, key=len, reverse=True)
    ]


def main():  # type: () -> int
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env-file", required=True)
    parser.add_argument("--secrets-file", help="raw generated secrets not present in any export")
    parser.add_argument("--output", required=True)
    arguments = parser.parse_args()
    values = _parse(arguments.env_file)
    if arguments.secrets_file:
        # Prefixed so the public-name filter cannot skip one of them.
        values.update(
            ("secret_%s" % name, value)
            for name, value in _parse(arguments.secrets_file).items()
        )
    expressions = build(values)
    with open(arguments.output, "w", encoding="utf-8") as stream:
        stream.write("".join("%s\n" % item for item in expressions))
    # Count only: printing an expression would print the secret it removes.
    sys.stdout.write("%d redaction expressions\n" % len(expressions))
    return 0


if __name__ == "__main__":
    sys.exit(main())
