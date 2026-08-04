"""V2RAY_SUBSCRIPTION ingestion and sanitized node inventory."""

from .audit import (
    MIHOMO_PARSER_IDENTITY,
    field_disposition_manifest,
    mihomo_parser_identity,
    subscription_field_disposition_manifest,
)
from .interfaces import NodeSource, ProxyNode, SubscriptionParser
from .manager import SubscriptionManager
from .model import NodeRecord, ParsedSubscription, SingleNodeSource, SubscriptionRecord
from .redaction import redact_bytes, redact_text, redact_url
from .transport import (
    DEFAULT_SUBSCRIPTION_PARSER,
    MIHOMO_SUBSCRIPTION_PARSER,
    MihomoSubscriptionParser,
    V2RaySubscriptionParser,
    fetch_subscription,
    parse_subscription_body,
    validate_source_url,
)

__all__ = [
    "NodeRecord",
    "NodeSource",
    "ParsedSubscription",
    "ProxyNode",
    "SubscriptionManager",
    "SubscriptionParser",
    "SubscriptionRecord",
    "SingleNodeSource",
    "DEFAULT_SUBSCRIPTION_PARSER",
    "MIHOMO_SUBSCRIPTION_PARSER",
    "MihomoSubscriptionParser",
    "V2RaySubscriptionParser",
    "MIHOMO_PARSER_IDENTITY",
    "field_disposition_manifest",
    "mihomo_parser_identity",
    "subscription_field_disposition_manifest",
    "fetch_subscription",
    "parse_subscription_body",
    "redact_bytes",
    "redact_text",
    "redact_url",
    "validate_source_url",
]
