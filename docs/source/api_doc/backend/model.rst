jerryproxy.backend.model
========================================================

.. currentmodule:: jerryproxy.backend.model

.. automodule:: jerryproxy.backend.model


PlatformInfo
-----------------------------------------------------

.. autoclass:: PlatformInfo
   :members: os_name,architecture,libc,key,asset_key,portable_asset_key,compatible_asset_keys


CatalogArtifact
-----------------------------------------------------

.. autoclass:: CatalogArtifact
   :members: backend,version,platform,asset_id,name,url,sha256,size,updated_at,verification,archive_format,executable,verified


CatalogVersion
-----------------------------------------------------

.. autoclass:: CatalogVersion
   :members: backend,version,tag,release_id,release_url,published_at,artifacts,artifact_for


InstalledBackend
-----------------------------------------------------

.. autoclass:: InstalledBackend
   :members: name,version,executable,manifest,asset_name,sha256,platform,executable_sha256


ActiveBackend
-----------------------------------------------------

.. autoclass:: ActiveBackend
   :members: name,version,executable,link,link_mode


BackendInventory
-----------------------------------------------------

.. autoclass:: BackendInventory
   :members: installed,active


CleanupResult
-----------------------------------------------------

.. autoclass:: CleanupResult
   :members: areas,targets_removed,bytes_reclaimed


RemovalResult
-----------------------------------------------------

.. autoclass:: RemovalResult
   :members: name,versions,cleanup
