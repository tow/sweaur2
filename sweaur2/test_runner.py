from __future__ import absolute_import

from .client import Client
from .client_store import ClientStore
from .exceptions import InvalidClient, InvalidGrant, InvalidRequest, InvalidScope, UnsupportedGrantType
from .policy import LowSecurityPolicy
from .processor import OAuth2Processor
from .token_store import TokenStore
from .tokens import AccessToken, RefreshToken


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


class TokenStoreForTest(TokenStore):
    def __init__(self):
        self.access_tokens = {}
        self.refresh_tokens = {}

    def save_access_token(self, token):
        self.access_tokens[token.token_string] = token
        if token.new_refresh_token:
            self.save_refresh_token(token.new_refresh_token)

    def save_refresh_token(self, token):
        self.refresh_tokens[token.token_string] = token

    def get_refresh_token(self, refresh_token_string):
        try:
            return self.refresh_tokens[refresh_token_string]
        except KeyError:
            raise self.NoSuchToken()

    def get_access_token(self, access_token_string):
        try:
            return self.access_tokens[access_token_string]
        except KeyError:
            raise self.NoSuchToken()


class PolicyForTest(LowSecurityPolicy):
    reject_client = False
    def refresh_token(self, client, scope):
        return client == TestOAuth2Processor.client_refresh_token

    def check_scope(self, client, scope):
        if self.reject_client:
            return False
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
        self.token_store = TokenStoreForTest()
        self.policy = PolicyForTest()
        self.processor = OAuth2Processor(client_store=self.client_store,
                                         token_store=self.token_store,
                                         policy=self.policy)

    def check_access_token(self, access_token, client, scope, refresh_token_expected, old_refresh_token):
        assert access_token.client == client
        assert access_token.scope == scope
        assert access_token.token_type == self.policy.token_type(client, scope)
        assert access_token.expiry_time == self.policy.expiry_time(client, scope)
        refresh_token = access_token.new_refresh_token
        if refresh_token_expected:
            assert refresh_token is not None
            assert refresh_token.client == client
            assert refresh_token.scope == scope
            assert refresh_token.access_token == access_token
        else:
            assert refresh_token is None
        assert access_token.old_refresh_token == old_refresh_token


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
        self.check_access_token(access_token, client, scope, refresh_token_expected=False, old_refresh_token=None)

    def testTokenOkNoScopeWithRefresh(self):
        client = self.client_refresh_token
        scope = None
        access_token = self.processor.oauth2_token_endpoint(grant_type='client_credentials',
                                                            client_id=client.client_id,
                                                            client_secret=client.client_secret)
        self.check_access_token(access_token, client, scope, refresh_token_expected=True, old_refresh_token=None)

    def testTokenOkWithScope(self):
        client = self.client_refresh_token
        scope = "SCOPE"
        access_token = self.processor.oauth2_token_endpoint(grant_type='client_credentials',
                                                            client_id=client.client_id,
                                                            client_secret=client.client_secret,
                                                            scope=scope)
        self.check_access_token(access_token, client, scope, refresh_token_expected=True, old_refresh_token=None)

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

    def testInvalidRefreshToken(self):
        try:
            self.processor.oauth2_token_endpoint(grant_type='refresh_token',
                                                 refresh_token='WRONG')
        except InvalidClient, e:
            assert e.error == 'invalid_client'
            assert e.error_description == ''
        else:
            assert False

    def testTokenOk(self):
        client = self.client_refresh_token
        scope = ''
        access_token = self.policy.new_access_token(client, scope)
        self.token_store.save_access_token(access_token)
        refresh_token = access_token.new_refresh_token
        new_access_token = self.processor.oauth2_token_endpoint(grant_type='refresh_token',
                                                                refresh_token=refresh_token.token_string)
        self.check_access_token(new_access_token, client, scope, refresh_token_expected=True, old_refresh_token=refresh_token)

    def testTokenOkWithScope(self):
        client = self.client_refresh_token
        scope = 'SCOPE'
        access_token = self.policy.new_access_token(client, scope)
        self.token_store.save_access_token(access_token)
        refresh_token = access_token.new_refresh_token
        new_access_token = self.processor.oauth2_token_endpoint(grant_type='refresh_token',
                                                                refresh_token=refresh_token.token_string,
                                                                scope=scope)
        self.check_access_token(new_access_token, client, scope, refresh_token_expected=True, old_refresh_token=refresh_token)

    def testReuseRefreshTokenFails(self):
        client = self.client_refresh_token
        scope = ''
        access_token = self.policy.new_access_token(client, scope)
        self.token_store.save_access_token(access_token)
        refresh_token = access_token.new_refresh_token
        new_access_token = self.processor.oauth2_token_endpoint(grant_type='refresh_token',
                                                                refresh_token=refresh_token.token_string)
        try:
            new_access_token = self.processor.oauth2_token_endpoint(grant_type='refresh_token',
                                                                    refresh_token=refresh_token.token_string)
        except InvalidGrant, e:
            assert e.error == 'invalid_grant'
            assert e.error_description == 'refresh_token is no longer valid'
        else:
            assert False

    def testRefreshTokenTooWideScopeFails(self):
        client = self.client_refresh_token
        scope = 'SCOPE'
        access_token = self.policy.new_access_token(client, scope)
        self.token_store.save_access_token(access_token)
        refresh_token = access_token.new_refresh_token
        try:
            new_access_token = self.processor.oauth2_token_endpoint(grant_type='refresh_token',
                                                                    refresh_token=refresh_token.token_string,
                                                                    scope=scope+" MORE_SCOPE")
        except InvalidScope, e:
            assert e.error == 'invalid_scope'
            assert e.error_description == ''
        else:
            assert False

    def testRefreshTokenPreservesScope(self):
        client = self.client_refresh_token
        scope = 'SCOPE'
        access_token = self.policy.new_access_token(client, scope)
        self.token_store.save_access_token(access_token)
        refresh_token = access_token.new_refresh_token
        # request next token without mentioning scope; it should be preserved.
        new_access_token = self.processor.oauth2_token_endpoint(grant_type='refresh_token',
                                                                refresh_token=refresh_token.token_string)
        self.check_access_token(new_access_token, client, scope, refresh_token_expected=True, old_refresh_token=refresh_token)

    def testRefreshTokenFailsAfterPolicyChange(self):
        client = self.client_refresh_token
        scope = ''
        access_token = self.policy.new_access_token(client, scope)
        self.token_store.save_access_token(access_token)
        refresh_token = access_token.new_refresh_token
        # change policy on the server to reduce the scope available to the client
        self.policy.reject_client = True
        try:
            new_access_token = self.processor.oauth2_token_endpoint(grant_type='refresh_token',
                                                                    refresh_token=refresh_token.token_string)
        except InvalidScope, e:
            assert e.error == 'invalid_scope'
            assert e.error_description == ''
        else:
            assert False
        self.policy.reject_client = False
