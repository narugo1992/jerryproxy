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

Standalone CI builds on Python 3.7 using ``ubuntu-22.04``, ``windows-2022``,
and ``macos-15-intel``. A second clean runner downloads and verifies the
first-stage artifact without checking out the source tree or installing Python
dependencies, extracts the release archive, then runs this self-check and the
public read-only CLI commands from the extracted binary.
