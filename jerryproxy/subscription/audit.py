"""Credential-free, source-pinned audit metadata for Mihomo NodeSets.

The URI envelope is validated by the bounded adapter, while Mihomo owns the
provider object and protocol interpretation at runtime.  This manifest records
the reviewed upstream identity and the disposition vocabulary used by the
contract; it never contains credential values or a second runtime schema.
"""

from copy import deepcopy

#: Credential-free source-pinned Mihomo parser identity.
MIHOMO_PARSER_IDENTITY = {
    "backend": "mihomo",
    "version": "1.19.29",
    "release_tag": "v1.19.29",
    "repository": "MetaCubeX/mihomo",
    "tag_commit": "e26714a181ac0e2fa803453c0a8e9a9ce94e31cb",
    "source_tree": "2487680d2def055568f3b50fcc61f931d70f6fa6",
    "parser_root": "config",
    "parser_root_tree": "650275c2bf3a465d2194d4b503e7049f9a452d0b",
    "parser_source_sha256": "cee079176a47ab45327972d72685ee8b816359f898079f6c8d83d026a6481afb",
    "source": "v2ray-uri-lines",
}


_FIELD_DISPOSITION_MANIFEST = {
    "identity": MIHOMO_PARSER_IDENTITY,
    "container": {
        "uri-lines": {"disposition": "preserve"},
        "base64-uri-lines": {"disposition": "replace"},
        "mihomo-provider": {"disposition": "preserve"},
    },
    "protocols": {
        "ss": {
            "method": "preserve",
            "password": "preserve",
            "server": "preserve",
            "port": "preserve",
            # URI fragments are local node labels; they are never sent in the
            # request target and are retained only as opaque source material.
            "fragment": "preserve",
        },
        "vmess": {
            "add": "preserve",
            "address": "preserve",
            "port": "preserve",
            "id": "preserve",
            "aid": "preserve",
            "net": "preserve",
            "tls": "preserve",
            "ps": "replace",
            "fragment": "preserve",
        },
        "vless": {
            "uuid": "preserve",
            "server": "preserve",
            "port": "preserve",
            "type": "preserve",
            "security": "preserve",
            "sni": "preserve",
            "fp": "preserve",
            "pbk": "preserve",
            "sid": "preserve",
            "flow": "preserve",
            "fragment": "preserve",
        },
    },
    "provider": {
        "uri": "preserve",
        "bytes": "preserve",
        "public_view": "replace",
    },
    "unsafe": {
        "rejected_fields": ["scripts", "hooks", "plugins", "controller", "tun", "listeners"],
        "rejected_protocols": ["ssr", "hysteria", "wireguard"],
        "credential_paths": ["password", "id", "uuid", "pbk", "sid"],
    },
    "field_universe": {
        "ss": ["method", "password", "server", "port", "fragment"],
        "vmess": ["add", "address", "port", "id", "aid", "net", "tls", "ps", "fragment"],
        "vless": [
            "uuid",
            "server",
            "port",
            "type",
            "security",
            "sni",
            "fp",
            "pbk",
            "sid",
            "flow",
            "fragment",
        ],
    },
    "one_field_oracle": {
        "accepted_dispositions": ["preserve", "replace", "reject"],
        "unknown_descendant": "reject",
        "duplicate_key": "reject",
        "credential_value": "opaque",
    },
}


def field_disposition_manifest():  # type: () -> dict
    """Return an independent credential-free copy of the field manifest."""

    return deepcopy(_FIELD_DISPOSITION_MANIFEST)


def subscription_field_disposition_manifest():  # type: () -> dict
    """Descriptive alias for :func:`field_disposition_manifest`."""

    return field_disposition_manifest()


def mihomo_parser_identity():  # type: () -> dict
    """Return the source-pinned Mihomo parser identity."""

    return dict(MIHOMO_PARSER_IDENTITY)
