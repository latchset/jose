=======
jansson
=======

Jansson `API documentation <https://jansson.readthedocs.io/en/2.9/apiref.html>`_.

Primer
======

.. c:type:: json_t

   This data structure is used throughout the library to represent all JSON
   values.

.. c:function:: void json_decref(json_t *json)

   Decrement the reference count of json. As soon as a call to json_decref()
   drops the reference count to zero, the value is destroyed and it can no
   longer be used.
