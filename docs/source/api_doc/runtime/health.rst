jerryproxy.runtime.health
========================================================

.. currentmodule:: jerryproxy.runtime.health

.. automodule:: jerryproxy.runtime.health


DEFAULT\_HEALTH\_TARGETS
-----------------------------------------------------

.. autodata:: DEFAULT_HEALTH_TARGETS
   :no-value:


\_\_all\_\_
-----------------------------------------------------

.. autodata:: __all__
   :no-value:


HealthTarget
-----------------------------------------------------

.. autoclass:: HealthTarget
   :members: name,url,status,maximum_bytes,sha256,required_header


TargetHealth
-----------------------------------------------------

.. autoclass:: TargetHealth
   :members: name,ok,header_latency,first_chunk_latency,speed_bytes_per_second,detail


HealthSnapshot
-----------------------------------------------------

.. autoclass:: HealthSnapshot
   :members: targets,passed,required,started_at,ok


ConnectivityProbe
-----------------------------------------------------

.. autoclass:: ConnectivityProbe
   :members: __init__,check


RecoveryPolicy
-----------------------------------------------------

.. autoclass:: RecoveryPolicy
   :members: health_interval,recovery_deadline,startup_retry_delays,same_node_delay,alternate_delays,refresh_on_failure,refresh_stale_seconds,failure_cooldown,__post_init__


RecoveryDeadline
-----------------------------------------------------

.. autoclass:: RecoveryDeadline
   :members: __init__,remaining,sleep


require\_health
-----------------------------------------------------

.. autofunction:: require_health
