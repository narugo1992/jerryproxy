jerryproxy.backend.activation
========================================================

.. currentmodule:: jerryproxy.backend.activation

.. automodule:: jerryproxy.backend.activation


PRECOMMIT\_PHASES
-----------------------------------------------------

.. autodata:: PRECOMMIT_PHASES
   :no-value:


PHASES
-----------------------------------------------------

.. autodata:: PHASES
   :no-value:


RECOVERY\_DIRECTIONS
-----------------------------------------------------

.. autodata:: RECOVERY_DIRECTIONS
   :no-value:


ActivationClassification
-----------------------------------------------------

.. autoclass:: ActivationClassification
   :members: link,manifest,link_candidate,manifest_candidate,link_evidence,manifest_evidence,link_candidate_evidence,manifest_candidate_evidence


ActivationRecoveryPlan
-----------------------------------------------------

.. autoclass:: ActivationRecoveryPlan
   :members: journal,direction,action,object_name,precondition


ActivationRecord
-----------------------------------------------------

.. autoclass:: ActivationRecord
   :members: kind,operation,journal_path,read_paths,write_paths,state,journal_identity,temporaries


ActivationTransaction
-----------------------------------------------------

.. autoclass:: ActivationTransaction
   :members: __init__,prepare,execute


recovery\_direction
-----------------------------------------------------

.. autofunction:: recovery_direction


load\_use\_journal
-----------------------------------------------------

.. autofunction:: load_use_journal


discover\_use\_journals
-----------------------------------------------------

.. autofunction:: discover_use_journals


classify\_public\_link
-----------------------------------------------------

.. autofunction:: classify_public_link


classify\_public\_manifest
-----------------------------------------------------

.. autofunction:: classify_public_manifest


classify\_candidate
-----------------------------------------------------

.. autofunction:: classify_candidate


classify\_activation
-----------------------------------------------------

.. autofunction:: classify_activation


plan\_activation\_recovery
-----------------------------------------------------

.. autofunction:: plan_activation_recovery


plan\_direction\_is\_previous
-----------------------------------------------------

.. autofunction:: plan_direction_is_previous


recover\_use\_record
-----------------------------------------------------

.. autofunction:: recover_use_record


durable\_replace
-----------------------------------------------------

.. autofunction:: durable_replace


recover\_use\_transactions
-----------------------------------------------------

.. autofunction:: recover_use_transactions
