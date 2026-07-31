jerryproxy.backend.archive\_preflight
========================================================

.. currentmodule:: jerryproxy.backend.archive_preflight

.. automodule:: jerryproxy.backend.archive_preflight


ZipPreflightEntry
-----------------------------------------------------

.. autoclass:: ZipPreflightEntry
   :members: name,local_header_offset,compressed_size,uncompressed_size,method,flags,crc32


ZipPreflightPlan
-----------------------------------------------------

.. autoclass:: ZipPreflightPlan
   :members: entries,central_directory_offset,central_directory_size,compressed_size,entry_count


GzipPreflightPlan
-----------------------------------------------------

.. autoclass:: GzipPreflightPlan
   :members: compressed_size,expanded_size,crc32


TarPreflightEntry
-----------------------------------------------------

.. autoclass:: TarPreflightEntry
   :members: name,is_directory,size,type_flag


TarPreflightPlan
-----------------------------------------------------

.. autoclass:: TarPreflightPlan
   :members: entries,compressed_size,raw_size,entry_count


preflight\_zip
-----------------------------------------------------

.. autofunction:: preflight_zip


preflight\_gzip
-----------------------------------------------------

.. autofunction:: preflight_gzip


preflight\_tar\_gzip
-----------------------------------------------------

.. autofunction:: preflight_tar_gzip
