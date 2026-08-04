Roadmap and WIP boundary
========================

Complete in the initial scaffold
--------------------------------

* Python package and CLI entry points;
* cross-platform home layout;
* Mihomo/sing-box/Xray/V2Ray backend registry;
* stable-only packaged catalogs and exact offline artifact selection;
* digest-verified downloads with GitHub API fingerprints preferred;
* safe extraction, immutable manifests, active links, removal;
* packaged-CLI local self-check, bounded built-in relay probes, and two-stage
  clean-runner validation;
* deterministic tests, package, docs, and CI definitions.

Implemented in the first usable proxy slice
--------------------------------------------

* bounded ``V2RAY_SUBSCRIPTION`` input with credential redaction and private
  home-local revisions;
* Mihomo 1.19.29 NodeSet projection and synchronous foreground ``server``;
* sanitized ``subscription`` and ``node list`` commands;
* global health quorum, same-node restart, deterministic alternate sweep, and
  one policy-controlled source refresh.

Later compatibility work
------------------------

* native Mihomo/Clash profiles and a controller/measurement API;
* Xray runtime driver for strict/new Xray-family cases;
* V2Ray legacy runtime driver;
* trusted configurable mirrors and explicit offline archives;
* signed standalone executables and PyPI Trusted Publishing.
* signed release artifacts and publication policy.
