from __future__ import absolute_import

from .client_store import ClientStoreSimpleDict
from .constructor_tests import constructor_for_token_endpoint
from .token_store import TokenStoreSimpleDict

globals().update(constructor_for_token_endpoint(TokenStoreSimpleDict(), ClientStoreSimpleDict()))
