"""Build a sed script that removes every generated value from captured logs.

The fixture servers emit access records, so a captured log can carry a password,
UUID, key, or short ID. Redaction that covers only the sentinel nonce would be
one value wide while the log surface is much wider.

The caller supplies every secret-bearing generated value, including the ones
that reach no service variable of their own — the Reality private key is passed
only to the vless fixture, and the SS password and VMess UUID otherwise exist
only inside base64 payloads. Deriving the set from what was generated, rather
than from what happens to be exported, is what makes the coverage complete, and
``make e2e_check`` enforces that in both directions.

Composite values are passed whole rather than split into parts. The Base64
subscription body contains every node URI, but none of them as plaintext, so
redacting the parts would not touch it.

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
        # A base64 value can appear with its padding stripped, for instance
        # after a round trip through a URL or a re-encoding layer. Matching only
        # the padded form would leave the unpadded one in the log.
        unpadded = value.rstrip("=")
        if unpadded != value and len(unpadded) >= _MINIMUM_TOKEN:
            secrets.add(unpadded)
    return [
        "s|%s|[REDACTED]|g" % _sed_literal(secret)
        for secret in sorted(secrets, key=len, reverse=True)
    ]


def main():  # type: () -> int
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env-file", required=True)
    parser.add_argument("--output", required=True)
    arguments = parser.parse_args()
    expressions = build(_parse(arguments.env_file))
    with open(arguments.output, "w", encoding="utf-8") as stream:
        stream.write("".join("%s\n" % item for item in expressions))
    # Count only: printing an expression would print the secret it removes.
    sys.stdout.write("%d redaction expressions\n" % len(expressions))
    return 0


if __name__ == "__main__":
    sys.exit(main())
