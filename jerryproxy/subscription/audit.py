"""Credential-free, source-pinned audit metadata for Mihomo NodeSets.

JerryProxy bounds and classifies the outer URI-line container only.  Mihomo
owns every protocol semantic decision at runtime.  This manifest records that
ownership boundary without duplicating protocol fields.

The protocol lists are derived from the transport allowlist rather than written
out again here.  Two hand-maintained copies drifted once already: `hysteria`
was listed as rejected while the allowlist admitted it.
"""

from copy import deepcopy

# Encrypted proxy schemes whose URI lines the qualified Mihomo release was
# measured to parse into a usable proxy. Membership is an observation, not an
# aspiration: `ssr://`, `wireguard://`, and the token-only `tuic://` dialect were
# measured to be dropped, so they stay out and are reported through the skip
# aggregate. Hysteria v1 is also absent: the backend loads it, but upstream has
# replaced it with v2, real subscriptions have effectively stopped shipping it,
# and supporting a protocol without a fixture proving it carries traffic is the
# claim this list exists to avoid.
#
# `http://` and `socks5://` are deliberately absent even though Mihomo does load
# them. They carry no encryption, so harvesting them out of a provider-controlled
# body is a poor default for a tool whose purpose is protecting traffic; and
# `http://` is also the scheme of a subscription source URL, so accepting it as a
# node would let an error page or a plain URL list be reported as N usable nodes.
# A deliberate plaintext proxy belongs in an explicit single-node input.
#
# JerryProxy still parses none of these. It forwards the URI verbatim, and the
# runtime session refuses to report readiness unless the backend confirms it
# accepted that exact line -- which is what makes widening this list safe.
#: Proxy `type:` values accepted from a provider document. These are the same
#: protocols as :data:`SUPPORTED_SCHEMES`, spelled the way the provider format
#: spells them: it says `hysteria2`, never the `hy2` URI alias, and it says
#: `ss` for Shadowsocks. Membership is the same measured claim -- each has a
#: data-plane fixture proving it carries traffic.
PROVIDER_TYPES = (
    "ss",
    "vmess",
    "vless",
    "trojan",
    "hysteria2",
    "tuic",
    "anytls",
)

SUPPORTED_SCHEMES = (
    "ss",
    "vmess",
    "vless",
    "trojan",
    "hysteria2",
    "hy2",
    "tuic",
    "anytls",
)

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
    "protocols": {scheme: "opaque-forwarded-to-mihomo" for scheme in SUPPORTED_SCHEMES},
    "provider": {
        "uri": "preserve",
        "bytes": "preserve",
        "public_view": "replace",
    },
    "unsafe": {
        "rejected_fields": ["scripts", "hooks", "plugins", "controller", "tun", "listeners"],
        # Measured against the qualified Mihomo release to be dropped rather
        # than parsed, so accepting them would report nodes that cannot carry
        # traffic. They are reported through the skip aggregate instead.
        "rejected_protocols": ["ssr", "wireguard"],
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
