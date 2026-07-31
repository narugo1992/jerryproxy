jerryproxy.backend.archive
========================================================

.. currentmodule:: jerryproxy.backend.archive

.. automodule:: jerryproxy.backend.archive


DEFAULT\_MAXIMUM\_EXTRACTED\_BYTES
-----------------------------------------------------

.. autodata:: DEFAULT_MAXIMUM_EXTRACTED_BYTES
   :no-value:


BAD\_GZIP\_FILE
-----------------------------------------------------

.. autodata:: BAD_GZIP_FILE
   :no-value:


ArchiveLimits
-----------------------------------------------------

.. autoclass:: ArchiveLimits
   :members: maximum_compressed_bytes,maximum_members,maximum_files,maximum_directories,maximum_path_depth,maximum_component_bytes,maximum_path_bytes,maximum_total_path_bytes,maximum_file_bytes,maximum_extracted_bytes,maximum_zip_central_directory_bytes,maximum_tar_stream_bytes,maximum_extension_bytes,maximum_total_extension_bytes


PinnedArchive
-----------------------------------------------------

.. autoclass:: PinnedArchive
   :members: __init__,__enter__,__exit__,extract


extract\_archive
-----------------------------------------------------

.. autofunction:: extract_archive


find\_executable
-----------------------------------------------------

.. autofunction:: find_executable
