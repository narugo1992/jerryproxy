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

``jerryproxy self-check`` performs a small network-free validation of the
runtime, platform mapping, private state tree, write access, backend registry,
and backend inventory. Every check reports ``OK`` or an exception type and
message; all checks run before the command returns a nonzero status on failure.

ANSI colors are selected automatically for terminal output. ``NO_COLOR``
disables colors, ``FORCE_COLOR=1`` enables them for redirected output, and
``self-check --color`` or ``self-check --no-color`` explicitly overrides the
automatic choice.

Standalone CI builds Linux entirely inside a digest-pinned official Python
3.7.11 Docker image based on Debian 9 and glibc 2.24. Windows and macOS use
Python 3.7 on their pinned hosted runners. A second clean runner downloads and
verifies the first-stage artifact without checking out the source tree or
installing Python dependencies. The Linux archive is then exercised in pinned
Ubuntu 18.04 and Debian 10 containers; both run ``self-check --color`` and
public read-only CLI commands from the same extracted binary.

The reproducible local Linux build entry point is:

.. code-block:: shell

   make build_linux

Docker is only a build requirement for this target. The resulting
``dist/jerryproxy`` executable does not require a local Python installation.
