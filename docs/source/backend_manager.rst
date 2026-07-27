Backend manager
===============

The backend manager keeps every version immutable below
``~/.jerryproxy/backends/<name>/<version>/`` and exposes the selected version
at ``~/.jerryproxy/bin/<name>``.

.. code-block:: shell

   jerryproxy backend supported
   jerryproxy backend install mihomo 1.19.29
   jerryproxy backend install mihomo 1.19.28 --no-activate
   jerryproxy backend switch mihomo 1.19.28
   jerryproxy backend current mihomo
   jerryproxy backend list mihomo

Activation uses an atomic relative symbolic link on Unix-like systems. Windows
without symlink privilege receives an atomic verified executable copy; the
active manifest records the selected version and ``link_mode`` so this
fallback is not mistaken for a real link.

Automatic installation accepts only an exact release asset with a valid
GitHub ``sha256:`` digest. Archive extraction rejects absolute paths, parent
traversal, archive symlinks, and special files.
