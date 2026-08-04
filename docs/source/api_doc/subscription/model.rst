jerryproxy.subscription.model
========================================================

.. currentmodule:: jerryproxy.subscription.model

.. automodule:: jerryproxy.subscription.model


NodeRecord
-----------------------------------------------------

.. autoclass:: NodeRecord
   :members: node_id,scheme,display,uri,occurrence,public,secret_uri


SingleNodeSource
-----------------------------------------------------

.. autoclass:: SingleNodeSource
   :members: node,iter_nodes


SubscriptionRecord
-----------------------------------------------------

.. autoclass:: SubscriptionRecord
   :members: name,subscription_id,revision,format,enabled,updated_at,nodes,source_url,body,node_count,public,iter_nodes


ParsedSubscription
-----------------------------------------------------

.. autoclass:: ParsedSubscription
   :members: format,body,records
