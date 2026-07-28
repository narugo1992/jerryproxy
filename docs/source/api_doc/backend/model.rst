jerryproxy.backend.model
========================================================

.. currentmodule:: jerryproxy.backend.model

.. automodule:: jerryproxy.backend.model


PlatformInfo
-----------------------------------------------------

.. autoclass:: PlatformInfo
   :members: os_name,architecture,libc,key


ReleaseAsset
-----------------------------------------------------

.. autoclass:: ReleaseAsset
   :members: name,url,sha256,size


InstalledBackend
-----------------------------------------------------

.. autoclass:: InstalledBackend
   :members: name,version,executable,manifest,asset_name,sha256,from_manifest


ActiveBackend
-----------------------------------------------------

.. autoclass:: ActiveBackend
   :members: name,version,executable,link,link_mode
