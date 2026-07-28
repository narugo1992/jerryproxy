Roadmap and WIP boundary
========================

Complete in the initial scaffold
--------------------------------

* Python package and CLI entry points;
* cross-platform home layout;
* Mihomo/Xray/V2Ray backend registry;
* exact release resolution and digest-verified downloads;
* safe extraction, immutable manifests, active links, removal;
* lightweight packaged-CLI self-check and two-stage clean-runner validation;
* deterministic tests, package, docs, and CI definitions.

Required before the first usable proxy alpha
--------------------------------------------

* managed subscription input and credential redaction;
* Mihomo config generation and authenticated controller integration;
* foreground ``run`` plus detached ``start``/``stop``/``status``;
* node list/select/test/refresh commands;
* legacy ``V2RAY_*`` and existing option migration;
* real pinned-backend integration tests on supported operating systems.

Later compatibility work
------------------------

* Xray runtime driver for strict/new Xray-family cases;
* V2Ray legacy runtime driver;
* trusted configurable mirrors and explicit offline archives;
* signed standalone executables and PyPI Trusted Publishing.
