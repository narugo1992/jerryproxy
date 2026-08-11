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
   :members: accepted,selected,bypassing


RuntimeDriver
-----------------------------------------------------

.. autoclass:: RuntimeDriver
   :members: name,projection,loaded_nodes,create_process,wait_ready,stop
