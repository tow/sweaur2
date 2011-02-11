from __future__ import absolute_import

from .client import Client
from .client_store import ClientStore
from .exceptions import InvalidClient, InvalidRequest, InvalidScope, UnsupportedGrantType
from .policy import LowSecurityPolicy
from .processor import OAuth2Processor
from .token_store import TokenStore


class ClientForTest(Client):
    def __init__(self, client_id, client_secret):
        self.client_id = client_id
        self.client_secret = client_secret

    def id_secret(self):
        return (self.client_id, self.client_secret)


class ClientStoreForTest(ClientStore):
    def get_client(self, client_id, client_secret):
        try:
            return TestOAuth2Processor.clients[(client_id, client_secret)]
        except KeyError:
            raise self.InvalidClient()


class PolicyForTest(LowSecurityPolicy):
    def refresh_token(self, client, scope):
        return client == TestOAuth2Processor.client_refresh_token

    def check_scope(self, client, scope):
        return client != TestOAuth2Processor.client_no_scopes


class TestOAuth2Processor(object):
    client_all_scopes = ClientForTest('ID1', 'SECRET1')
    client_no_scopes = ClientForTest('ID2', 'SECRET2')
    client_refresh_token = ClientForTest('ID3', 'SECRET3')
    invalid_client = ClientForTest('NOID', 'NOSECRET')
    clients = {client_all_scopes.id_secret(): client_all_scopes,
               client_no_scopes.id_secret(): client_no_scopes,
               client_refresh_token.id_secret(): client_refresh_token}

    def setUp(self):
        self.client_store = ClientStoreForTest()
        self.token_store = TokenStore()
        self.policy = PolicyForTest()
        self.processor = OAuth2Processor(client_store=self.client_store,
                                         token_store=self.token_store,
                                         policy=self.policy)

    def check_access_token(self, access_token, client, scope, refresh_token_expected):
        assert access_token.client == client
        assert access_token.scope == scope
        assert access_token.token_type == self.policy.token_type(client, scope)
        assert access_token.expiry_time == self.policy.expiry_time(client, scope)
        assert access_token.old_refresh_token is None
        refresh_token = access_token.new_refresh_token
        if refresh_token_expected:
            assert refresh_token is not None
            assert refresh_token.client == client
            assert refresh_token.scope == scope
            assert refresh_token.token_type == self.policy.token_type(client, scope)
            assert refresh_token.access_token == access_token
        else:
            assert refresh_token is None


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


class TestClientCredentials(TestOAuth2Processor):
    def testNoClientId(self):
        try:
            self.processor.oauth2_token_endpoint(grant_type='client_credentials',
                                                 client_secret=self.invalid_client.client_secret)
        except InvalidRequest, e:
            assert e.error == 'invalid_request'
            assert e.error_description == 'No client_id specified'
        else:
            assert False

    def testNoClientSecret(self):
        try:
            self.processor.oauth2_token_endpoint(grant_type='client_credentials',
                                                 client_id=self.invalid_client.client_id)
        except InvalidRequest, e:
            assert e.error == 'invalid_request'
            assert e.error_description == 'No client_secret specified'
        else:
            assert False

    def testInvalidClient(self):
        try:
            self.processor.oauth2_token_endpoint(grant_type='client_credentials',
                                                 client_id=self.invalid_client.client_id,
                                                 client_secret=self.invalid_client.client_secret)
        except InvalidClient, e:
            assert e.error == 'invalid_client'
            assert e.error_description == ''

    def testTokenOkNoScopeNoRefresh(self):
        client = self.client_all_scopes
        scope = None
        access_token = self.processor.oauth2_token_endpoint(grant_type='client_credentials',
                                                            client_id=client.client_id,
                                                            client_secret=client.client_secret)
        self.check_access_token(access_token, client, scope, refresh_token_expected=False)

    def testTokenOkNoScopeWithRefresh(self):
        client = self.client_refresh_token
        scope = None
        access_token = self.processor.oauth2_token_endpoint(grant_type='client_credentials',
                                                            client_id=client.client_id,
                                                            client_secret=client.client_secret)
        self.check_access_token(access_token, client, scope, refresh_token_expected=True)

    def testTokenOkWithScope(self):
        client = self.client_refresh_token
        scope = "SCOPE"
        access_token = self.processor.oauth2_token_endpoint(grant_type='client_credentials',
                                                            client_id=client.client_id,
                                                            client_secret=client.client_secret,
                                                            scope=scope)
        self.check_access_token(access_token, client, scope, refresh_token_expected=True)

    def testTokenFailWithScope(self):
        client = self.client_no_scopes
        scope = "SCOPE"
        try:
            self.processor.oauth2_token_endpoint(grant_type='client_credentials',
                                                 client_id=client.client_id,
                                                 client_secret=client.client_secret,
                                                 scope=scope)
        except InvalidScope, e:
            assert e.error == 'invalid_scope'
        else:
            assert False


class TestRefreshToken(TestOAuth2Processor):
    def testNoRefreshToken(self):
        try:
            self.processor.oauth2_token_endpoint(grant_type='refresh_token')
        except InvalidRequest, e:
            assert e.error == 'invalid_request'
            assert e.error_description == 'No refresh_token specified'
        else:
            assert False
