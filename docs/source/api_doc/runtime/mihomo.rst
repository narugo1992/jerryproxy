jerryproxy.runtime.mihomo
========================================================

.. currentmodule:: jerryproxy.runtime.mihomo

.. automodule:: jerryproxy.runtime.mihomo


QUALIFIED\_VERSION
-----------------------------------------------------

.. autodata:: QUALIFIED_VERSION
   :no-value:


MAXIMUM\_LOG\_BYTES
-----------------------------------------------------

.. autodata:: MAXIMUM_LOG_BYTES
   :no-value:


MAXIMUM\_BACKEND\_LINE\_BYTES
-----------------------------------------------------

.. autodata:: MAXIMUM_BACKEND_LINE_BYTES
   :no-value:


LISTENER\_PROTOCOLS
-----------------------------------------------------

.. autodata:: LISTENER_PROTOCOLS
   :no-value:


LISTENER\_ADDRESSES
-----------------------------------------------------

.. autodata:: LISTENER_ADDRESSES
   :no-value:


MihomoDriver
-----------------------------------------------------

.. autoclass:: MihomoDriver
   :members: __init__,name,projection,create_process,wait_ready,stop


MihomoProcess
-----------------------------------------------------

.. autoclass:: MihomoProcess
   :members: __init__,set_log_lock,start,wait_ready,stop


reserve\_loopback\_port
-----------------------------------------------------

.. autofunction:: reserve_loopback_port


build\_provider\_config
-----------------------------------------------------

.. autofunction:: build_provider_config


build\_environment
-----------------------------------------------------

.. autofunction:: build_environment
