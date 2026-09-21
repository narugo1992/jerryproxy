jerryproxy.runtime.interfaces
========================================================

.. currentmodule:: jerryproxy.runtime.interfaces

.. automodule:: jerryproxy.runtime.interfaces


RuntimeProjection
-----------------------------------------------------

.. autoclass:: RuntimeProjection
   :members: config,provider


LoadedNodes
-----------------------------------------------------

.. autoclass:: LoadedNodes
   :members: accepted,selected,bypassing,identities


RuntimeDriver
-----------------------------------------------------

.. autoclass:: RuntimeDriver
   :members: name,projection,loaded_nodes,reload_provider,create_process,wait_ready,stop
