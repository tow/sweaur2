from __future__ import absolute_import

from .client_store import ClientStore
from .exceptions import InvalidRequest, UnsupportedGrantType
from .policy import LowSecurityPolicy
from .processor import OAuth2Processor
from .token_store import TokenStore


class TestObviousFailures(object):
    def setUp(self):
        self.processor = OAuth2Processor(TokenStore(), ClientStore(), LowSecurityPolicy())

    def testNoGrantType(self):
       try:
           self.processor.oauth2_token_endpoint()
       except InvalidRequest, e:
           assert e.error == 'invalid_request'
       else:
           assert False

    def testInvalidGrantType(self):
       try:
           self.processor.oauth2_token_endpoint(grant_type='gimmegimme')
       except UnsupportedGrantType, e:
           assert e.error == 'unsupported_grant_type'
       else:
           assert False
