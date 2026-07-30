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

Required before the first usable proxy alpha
--------------------------------------------

* managed subscription input and credential redaction;
* Mihomo config generation and authenticated controller integration;
* foreground ``run`` plus detached ``start``/``stop``/``status``;
* node list/select/test/refresh commands;
* legacy ``V2RAY_*`` and existing option migration;
* signed release artifacts and publication policy.

Later compatibility work
------------------------

* Xray runtime driver for strict/new Xray-family cases;
* V2Ray legacy runtime driver;
* trusted configurable mirrors and explicit offline archives;
* signed standalone executables and PyPI Trusted Publishing.
