from __future__ import absolute_import

from .client_store import ClientStoreSimpleDict
from .constructor_test_token_endpoint import constructor
from .token_store import TokenStoreSimpleDict

globals().update(constructor(TokenStoreSimpleDict(), ClientStoreSimpleDict()))
