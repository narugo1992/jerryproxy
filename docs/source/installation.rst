Installation
============

JerryProxy supports Python 3.7 and newer and is designed as a pure-Python
wheel. It is not published to PyPI yet.

Development installation
------------------------

.. code-block:: shell

   python -m pip install -e .
   python -m pip install -r requirements-test.txt
   jerryproxy --help

All mutable state defaults to ``~/.jerryproxy``. Override it explicitly:

.. code-block:: shell

   JERRYPROXY_HOME=/private/path jerryproxy doctor
   jerryproxy --home /private/path doctor
   jerryproxy --home /private/path self-check

The CLI source is platform-independent. Backend availability is separately
determined from exact upstream release assets for the current OS and CPU.

Packaged CLI self-check
-----------------------

``jerryproxy self-check`` validates the runtime, platform mapping, private state
tree, write access, backend registry, ``filelock`` compatibility, and one
lock-consistent backend inventory. It also exercises install and activation
crash recovery in an isolated temporary JerryProxy home without changing the
configured home. It then streams a fixed 1 MiB Range from a
pinned public Xray release through each of the three built-in relays. Each relay
request has a five-second network timeout. The check requires an HTTPS redirect
chain, HTTP 206, the exact ``Content-Range`` and byte count, and the pinned
slice SHA-256. It reports response-header latency, first-chunk latency, and the
speed of the remaining chunks separately.

Results are ``OK`` (green), ``WARN`` (yellow), ``FAIL`` (red), or ``ERR``
(red). Relay timeout, transport, HTTP, or content failures are ``WARN`` and do
not make the command fail. Only ``FAIL`` and ``ERR`` produce a nonzero exit
status. A fully successful run transfers 3 MiB; it never downloads or starts a
complete backend and does not mutate backend state. Standard Requests proxy and
CA environment behavior remains active.

Python 3.7 through 3.9 use the newest ``filelock`` lines that still support
those interpreters. Those legacy lines are affected by CVE-2025-68146, so the
check reports ``WARN`` and recommends Python 3.10+; the warning does not block
otherwise supported operations. Python 3.10+ uses ``filelock>=3.30`` with the
dependency's upstream fork-ownership protection.

Standalone executables use Python 3.7 to retain the documented legacy operating
system baseline, so they also bundle a legacy ``filelock`` line and report the
warning. Use the Python 3.10+ pip installation when the upstream lock hardening
is more important than legacy standalone compatibility.

ANSI colors are selected automatically for terminal output. ``NO_COLOR``
disables colors, ``FORCE_COLOR=1`` enables them for redirected output, and
``self-check --color`` or ``self-check --no-color`` explicitly overrides the
automatic choice.

Standalone CI builds Linux entirely inside a digest-pinned official Python
3.7.11 Docker image based on Debian 9 and glibc 2.24. Windows and macOS use
Python 3.7 on their pinned hosted runners. A second clean runner downloads and
verifies the first-stage artifact without checking out the source tree or
installing Python dependencies. The Linux archive is then exercised in seven
digest-pinned containers: Ubuntu 18.04, Ubuntu 20.04, Debian 10, Oracle Linux
7, CentOS 7, Amazon Linux 2, and openSUSE Leap 15.0. Every job verifies the
distribution identity, runs ``self-check --color``, and exercises public
read-only CLI commands from the same extracted binary. The Enterprise Linux 7
jobs enforce the current glibc 2.17 compatibility boundary.

Several historical targets are upstream-EOL. Inclusion in this matrix proves
binary compatibility for the staged JerryProxy artifact; it does not imply
that the distribution still receives vendor security maintenance.

The reproducible local Linux build entry point is:

.. code-block:: shell

   make build_linux

Docker is only a build requirement for this target. The resulting
``dist/jerryproxy`` executable does not require a local Python installation.
