"""Credential-free, source-pinned audit metadata for Mihomo NodeSets.

JerryProxy bounds and classifies the outer URI-line container only.  Mihomo
owns every SS, VMess, and VLESS semantic decision at runtime.  This manifest
records that ownership boundary without duplicating protocol fields.
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
        "ss": "opaque-forwarded-to-mihomo",
        "vmess": "opaque-forwarded-to-mihomo",
        "vless": "opaque-forwarded-to-mihomo",
    },
    "provider": {
        "uri": "preserve",
        "bytes": "preserve",
        "public_view": "replace",
    },
    "unsafe": {
        "rejected_fields": ["scripts", "hooks", "plugins", "controller", "tun", "listeners"],
        "rejected_protocols": ["ssr", "hysteria", "wireguard"],
        "credential_material": "private-only",
    },
    "semantic_authority": {
        "owner": "mihomo",
        "version": "1.19.29",
        "unknown_uri_options": "preserve-and-defer",
        "credential_value": "opaque",
    },
}


def field_disposition_manifest():  # type: () -> dict
    """Return an independent credential-free container ownership manifest."""

    return deepcopy(_FIELD_DISPOSITION_MANIFEST)


def subscription_field_disposition_manifest():  # type: () -> dict
    """Descriptive alias for :func:`field_disposition_manifest`."""

    return field_disposition_manifest()


def mihomo_parser_identity():  # type: () -> dict
    """Return the source-pinned Mihomo parser identity."""

    return dict(MIHOMO_PARSER_IDENTITY)
