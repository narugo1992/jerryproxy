jerryproxy.backend.relay
========================================================

.. currentmodule:: jerryproxy.backend.relay

.. automodule:: jerryproxy.backend.relay


ALLOWED\_PATTERNS
-----------------------------------------------------

.. autodata:: ALLOWED_PATTERNS
   :no-value:


RELAY\_PROBE\_URL
-----------------------------------------------------

.. autodata:: RELAY_PROBE_URL
   :no-value:


RELAY\_PROBE\_SIZE
-----------------------------------------------------

.. autodata:: RELAY_PROBE_SIZE
   :no-value:


RELAY\_PROBE\_BYTES
-----------------------------------------------------

.. autodata:: RELAY_PROBE_BYTES
   :no-value:


RELAY\_PROBE\_SHA256
-----------------------------------------------------

.. autodata:: RELAY_PROBE_SHA256
   :no-value:


RelayProfile
-----------------------------------------------------

.. autoclass:: RelayProfile
   :members: name,base_url,pattern,built_in


DownloadSource
-----------------------------------------------------

.. autoclass:: DownloadSource
   :members: label,url


iter\_builtin\_relays
-----------------------------------------------------

.. autofunction:: iter_builtin_relays


get\_builtin\_relay
-----------------------------------------------------

.. autofunction:: get_builtin_relay


custom\_relay
-----------------------------------------------------

.. autofunction:: custom_relay


render\_relay\_url
-----------------------------------------------------

.. autofunction:: render_relay_url


build\_download\_sources
-----------------------------------------------------

.. autofunction:: build_download_sources
