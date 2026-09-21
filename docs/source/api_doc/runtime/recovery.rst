jerryproxy.runtime.recovery
========================================================

.. currentmodule:: jerryproxy.runtime.recovery

.. automodule:: jerryproxy.runtime.recovery


DEFAULT\_RETRY\_CHAIN
-----------------------------------------------------

.. autodata:: DEFAULT_RETRY_CHAIN
   :no-value:


RETRY\_POLICIES
-----------------------------------------------------

.. autodata:: RETRY_POLICIES
   :no-value:


RetrySchedule
-----------------------------------------------------

.. autoclass:: RetrySchedule
   :members: __init__,begin_sweep,update,record,wait_seconds,next


RetryBackoff
-----------------------------------------------------

.. autoclass:: RetryBackoff
   :members: __init__,healthy,failed


parse\_retry\_chain
-----------------------------------------------------

.. autofunction:: parse_retry_chain
