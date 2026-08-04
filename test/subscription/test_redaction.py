from jerryproxy.subscription.redaction import redact_text


def test_redaction_does_not_treat_opaque_ss_or_vmess_authority_as_host():
    ss = "ss://YWVzLTI1Ni1nY206c2VjcmV0QDE5Mi4wLjIuMTo0NDM#node"
    vmess = "vmess://eyJhZGQiOiIxOTIuMC4yLjIiLCJpZCI6IjU1NTU1NTU1LTU1NTUtNTU1NS01NTU1LTU1NTU1NTU1NTU1In0="
    rendered = redact_text("%s %s" % (ss, vmess))
    assert "YWVzLTI1Ni1nY206" not in rendered
    assert "eyJhZGQiOi" not in rendered
    assert "ss://[REDACTED]" in rendered
    assert "vmess://[REDACTED]" in rendered


def test_redaction_covers_non_rfc_variant_uuid_values():
    rendered = redact_text("id=55555555-5555-5555-5555-555555555555")
    assert "55555555-5555" not in rendered
    assert "[REDACTED UUID]" in rendered


def test_redaction_covers_structured_backend_secret_forms():
    rendered = redact_text(
        '{"password":"secret","public-key":"key-value"} public-key: plain-key token=abc'
    )
    assert "secret" not in rendered
    assert "key-value" not in rendered
    assert "plain-key" not in rendered
    assert "token=[REDACTED]" in rendered


def test_redaction_covers_non_http_proxy_url_schemes():
    rendered = redact_text(
        "socks5h://user:password@example.test:1080?token=secret "
        "ssh://name:secret@example.test:22/path "
        "wss://name:secret@example.test:443/path?token=secret"
    )
    assert "user:password" not in rendered
    assert "token=secret" not in rendered
    assert "name:secret" not in rendered
    assert "socks5h://example.test:1080" in rendered
    assert "ssh://example.test:22" in rendered
    assert "wss://example.test:443" in rendered
