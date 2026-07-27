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

The CLI source is platform-independent. Backend availability is separately
determined from exact upstream release assets for the current OS and CPU.
