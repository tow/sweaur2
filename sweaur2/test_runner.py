from __future__ import absolute_import

from .client import Client
from .client_store import ClientStore
from .exceptions import InvalidClient, InvalidRequest, UnsupportedGrantType
from .policy import LowSecurityPolicy
from .processor import OAuth2Processor
from .token_store import TokenStore


class ClientForTest(Client):
    pass

class ClientStoreForTest(ClientStore):
    clients = {('ID', 'SECRET'): Client()}
    def get_client(self, client_id, client_secret):
        try:
            return self.clients[(client_id, client_secret)]
        except KeyError:
            raise self.InvalidClient()


class TestOAuth2Processor(object):
    def setUp(self):
        self.processor = OAuth2Processor(client_store=ClientStoreForTest(),
                                         token_store=TokenStore(),
                                         policy=LowSecurityPolicy())


class TestObviousFailures(TestOAuth2Processor):
    def testNoGrantType(self):
       try:
           self.processor.oauth2_token_endpoint()
       except InvalidRequest, e:
           assert e.error == 'invalid_request'
           assert e.error_description == 'No grant_type specified'
       else:
           assert False

    def testInvalidGrantType(self):
       try:
           self.processor.oauth2_token_endpoint(grant_type='gimmegimme')
       except UnsupportedGrantType, e:
           assert e.error == 'unsupported_grant_type'
           assert e.error_description == ''
       else:
           assert False


class TestClientCredentialFailures(TestOAuth2Processor):
    def testNoClientId(self):
        try:
            self.processor.oauth2_token_endpoint(grant_type='client_credentials', client_secret='SECRET')
        except InvalidRequest, e:
            assert e.error == 'invalid_request'
            assert e.error_description == 'No client_id specified'
        else:
            assert False

    def testNoClientSecret(self):
        try:
            self.processor.oauth2_token_endpoint(grant_type='client_credentials', client_id='ID')
        except InvalidRequest, e:
            assert e.error == 'invalid_request'
            assert e.error_description == 'No client_secret specified'
        else:
            assert False

    def testInvalidClient(self):
        try:
            self.processor.oauth2_token_endpoint(grant_type='client_credentials', client_id='NOID', client_secret='NOSECRET')
        except InvalidClient, e:
            assert e.error == 'invalid_client'
            assert e.error_description == ''
