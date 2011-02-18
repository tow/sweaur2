from __future__ import absolute_import

from .client import SimpleClient
from .client_store import ClientStore
from .exceptions import InvalidClient, InvalidGrant, InvalidRequest, InvalidScope, UnsupportedGrantType
from .policy import LowSecurityPolicy
from .processor import OAuth2Processor
from .request import Request
from .request_handler import RequestHandler
from .token_store import TokenStoreSimpleDict
from .tokens import Token, AccessToken, RefreshToken


client_all_scopes_data = SimpleClient('ID1', 'SECRET1')
client_no_scopes_data = SimpleClient('ID2', 'SECRET2')
client_refresh_token_data = SimpleClient('ID3', 'SECRET3')
invalid_client_data = SimpleClient('NOID', 'NOSECRET')


class PolicyForTest(LowSecurityPolicy):
    reject_client = False
    def refresh_token(self, client, scope):
        return client.client_id == client_refresh_token_data.client_id

    def scope_for_access_token(self, client, scope):
        if self.reject_client:
            return False
        return client.client_id != client_no_scopes_data.client_id


def constructor_for_token_endpoint(token_store, client_store):
    class TestOAuth2Processor(object):

        def setUp(self):
            self.token_store = token_store
            self.client_store = client_store

            self.client_all_scopes = self.client_store.make_client(client_all_scopes_data)
            self.client_no_scopes = self.client_store.make_client(client_no_scopes_data)
            self.client_refresh_token = self.client_store.make_client(client_refresh_token_data)
            self.invalid_client = self.client_store.make_client(invalid_client_data, active=False)
            self.policy = PolicyForTest()
            self.processor = OAuth2Processor(client_store=self.client_store,
                                             token_store=self.token_store,
                                             policy=self.policy)

        def tearDown(self):
            self.client_store.delete_client(client_all_scopes_data)
            self.client_store.delete_client(client_no_scopes_data)
            self.client_store.delete_client(client_refresh_token_data)
            self.client_store.delete_client(invalid_client_data)

        def check_access_token(self, access_token, client, scope, refresh_token_expected, old_refresh_token_string):
            assert access_token.client.client_id == client.client_id
            assert access_token.scope == scope
            assert access_token.token_type == self.policy.token_type(client, scope)
            assert access_token.expires_in == self.policy.expires_in(client, scope)
            if refresh_token_expected:
                refresh_token = self.token_store.get_refresh_token(access_token.new_refresh_token_string)
                assert refresh_token is not None
                assert refresh_token.client.client_id == client.client_id
                assert refresh_token.scope == scope
                assert refresh_token.old_access_token_string == access_token.token_string
            else:
                assert access_token.new_refresh_token_string is None
            assert access_token.old_refresh_token_string == old_refresh_token_string


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
            client_data = client_all_scopes_data
            try:
                self.processor.oauth2_token_endpoint(grant_type='client_credentials',
                                                     client_secret=client_data.client_secret)
            except InvalidRequest, e:
                assert e.error == 'invalid_request'
                assert e.error_description == 'No client_id specified'
            else:
                assert False

        def testNoClientSecret(self):
            client_data = client_all_scopes_data
            try:
                self.processor.oauth2_token_endpoint(grant_type='client_credentials',
                                                     client_id=client_data.client_id)
            except InvalidRequest, e:
                assert e.error == 'invalid_request'
                assert e.error_description == 'No client_secret specified'
            else:
                assert False

        def testInvalidClient(self):
            client_data = invalid_client_data
            try:
                self.processor.oauth2_token_endpoint(grant_type='client_credentials',
                                                     client_id=client_data.client_id,
                                                     client_secret=client_data.client_secret)
            except InvalidClient, e:
                assert e.error == 'invalid_client'
                assert e.error_description == ''

        def testTokenOkNoScopeNoRefresh(self):
            client_data = client_all_scopes_data
            scope = None
            access_token = self.processor.oauth2_token_endpoint(grant_type='client_credentials',
                                                                client_id=client_data.client_id,
                                                                client_secret=client_data.client_secret)
            client = self.client_store.get_client(client_data.client_id, client_data.client_secret)
            self.check_access_token(access_token, client, scope, refresh_token_expected=False, old_refresh_token_string=None)

        def testTokenOkNoScopeWithRefresh(self):
            client_data = client_refresh_token_data
            scope = None
            access_token = self.processor.oauth2_token_endpoint(grant_type='client_credentials',
                                                                client_id=client_data.client_id,
                                                                client_secret=client_data.client_secret)
            client = self.client_store.get_client(client_data.client_id, client_data.client_secret)
            self.check_access_token(access_token, client, scope, refresh_token_expected=True, old_refresh_token_string=None)

        def testTokenOkWithScope(self):
            client_data = client_refresh_token_data
            scope = "SCOPE"
            access_token = self.processor.oauth2_token_endpoint(grant_type='client_credentials',
                                                                client_id=client_data.client_id,
                                                                client_secret=client_data.client_secret,
                                                                scope=scope)
            client = self.client_store.get_client(client_data.client_id, client_data.client_secret)
            self.check_access_token(access_token, client, scope, refresh_token_expected=True, old_refresh_token_string=None)

        def testTokenFailWithScope(self):
            client_data = client_no_scopes_data
            scope = "SCOPE"
            try:
                self.processor.oauth2_token_endpoint(grant_type='client_credentials',
                                                     client_id=client_data.client_id,
                                                     client_secret=client_data.client_secret,
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
            _, access_token, new_refresh_token = Token.make_new_access_token(self.policy, client, scope, None)
            self.token_store.save_refresh_token(new_refresh_token)
            self.token_store.save_access_token(access_token)
            new_access_token = self.processor.oauth2_token_endpoint(grant_type='refresh_token',
                                                                    refresh_token=new_refresh_token.token_string)
            self.check_access_token(new_access_token, client, scope, refresh_token_expected=True, old_refresh_token_string=new_refresh_token.token_string)

        def testTokenOkWithScope(self):
            client = self.client_refresh_token
            scope = 'SCOPE'
            _, access_token, new_refresh_token = Token.make_new_access_token(self.policy, client, scope, None)
            self.token_store.save_refresh_token(new_refresh_token)
            self.token_store.save_access_token(access_token)
            refresh_token = self.token_store.get_refresh_token(access_token.new_refresh_token_string)
            new_access_token = self.processor.oauth2_token_endpoint(grant_type='refresh_token',
                                                                    refresh_token=refresh_token.token_string,
                                                                    scope=scope)
            self.check_access_token(new_access_token, client, scope, refresh_token_expected=True, old_refresh_token_string=new_refresh_token.token_string)

        def testReuseRefreshTokenFails(self):
            client = self.client_refresh_token
            scope = ''
            _, access_token, new_refresh_token = Token.make_new_access_token(self.policy, client, scope, None)
            self.token_store.save_refresh_token(new_refresh_token)
            self.token_store.save_access_token(access_token)
            new_access_token = self.processor.oauth2_token_endpoint(grant_type='refresh_token',
                                                                    refresh_token=new_refresh_token.token_string)
            try:
                new_access_token = self.processor.oauth2_token_endpoint(grant_type='refresh_token',
                                                                        refresh_token=new_refresh_token.token_string)
            except InvalidGrant, e:
                assert e.error == 'invalid_grant'
                assert e.error_description == 'refresh_token is no longer valid'
            else:
                assert False

        def testRefreshTokenTooWideScopeFails(self):
            client = self.client_refresh_token
            scope = 'SCOPE'
            _, access_token, new_refresh_token = Token.make_new_access_token(self.policy, client, scope, None)
            self.token_store.save_refresh_token(new_refresh_token)
            self.token_store.save_access_token(access_token)
            try:
                new_access_token = self.processor.oauth2_token_endpoint(grant_type='refresh_token',
                                                                        refresh_token=new_refresh_token.token_string,
                                                                        scope=scope+" MORE_SCOPE")
            except InvalidScope, e:
                assert e.error == 'invalid_scope'
                assert e.error_description == ''
            else:
                assert False

        def testRefreshTokenPreservesScope(self):
            client = self.client_refresh_token
            scope = 'SCOPE'
            _, access_token, new_refresh_token = Token.make_new_access_token(self.policy, client, scope, None)
            self.token_store.save_refresh_token(new_refresh_token)
            self.token_store.save_access_token(access_token)
            # request next token without mentioning scope; it should be preserved.
            new_access_token = self.processor.oauth2_token_endpoint(grant_type='refresh_token',
                                                                    refresh_token=new_refresh_token.token_string)
            self.check_access_token(new_access_token, client, scope, refresh_token_expected=True, old_refresh_token_string=new_refresh_token.token_string)

        def testRefreshTokenFailsAfterPolicyChange(self):
            client = self.client_refresh_token
            scope = ''
            _, access_token, new_refresh_token = Token.make_new_access_token(self.policy, client, scope, None)
            self.token_store.save_refresh_token(new_refresh_token)
            self.token_store.save_access_token(access_token)
            # change policy on the server to reduce the scope available to the client
            self.policy.reject_client = True
            try:
                new_access_token = self.processor.oauth2_token_endpoint(grant_type='refresh_token',
                                                                        refresh_token=new_refresh_token.token_string)
            except InvalidScope, e:
                assert e.error == 'invalid_scope'
                assert e.error_description == ''
            else:
                assert False
            self.policy.reject_client = False

    return {
        'TestObviousFailures':TestObviousFailures,
        'TestClientCredentials':TestClientCredentials,
        'TestRefreshToken':TestRefreshToken,
        }


def constructor_for_bearer_checks(token_store, client_store):
    class TestChecker(object):

        def setUp(self):
            self.token_store = token_store
            self.client_store = client_store

            self.client = self.client_store.make_client(SimpleClient('client_id', 'client_secret'))
            self.access_token_all_ok = AccessToken(self.client, 'scope', 'bearer', 3600, 'ACCESS_TOKEN', None, None, body=True, uri=True)
            self.access_token_only_header = AccessToken(self.client, 'scope', 'bearer', 3600, 'HEADER_TOKEN', None, None, body=False, uri=False)
            self.token_store.save_access_token(self.access_token_all_ok)
            self.token_store.save_access_token(self.access_token_only_header)
            self.policy = LowSecurityPolicy()
            self.request_handler = RequestHandler(policy=self.policy, token_store=self.token_store, allowed_token_types=('bearer',))

        def tearDown(self):
            self.client_store.delete_client(self.client)


    class TestBasicChecks(TestChecker):
        def test_check_request_fails_if_wrong_auth_type(self):
            request = Request('GET', 'http://example.com/query/?q=test&fmt=json', {'Host': 'example.com', 'Authorization':'BearerMISSPELT ACCESS_TOKEN'}, '')
            try:
                token = self.request_handler.check_request(request=request)
            except self.request_handler.AuthenticationNotFound:
                pass
            else:
                assert False

        def test_check_request_fails_if_absent(self):
            request = Request('GET', 'http://example.com/query/?q=test&fmt=json', {'Host': 'example.com'}, '')
            try:
                token = self.request_handler.check_request(request=request)
            except self.request_handler.AuthenticationNotFound:
                pass
            else:
                assert False


    class TestCheckingHeader(TestChecker):

        def test_check_request_header_ok(self):
            request = Request('GET', 'http://example.com/query/?q=test&fmt=json', {'Host': 'example.com', 'Authorization':'Bearer ACCESS_TOKEN'}, '')
            token = self.request_handler.check_request(request=request)
            assert token.client.client_id == self.client.client_id
            assert token.scope == 'scope'

        def test_check_request_header_fails_if_wrong(self):
            request = Request('GET', 'http://example.com/query/?q=test&fmt=json', {'Host': 'example.com', 'Authorization':'Bearer ANOTHER_TOKEN'}, '')
            try:
                token = self.request_handler.check_request(request=request)
            except InvalidClient:
                pass
            else:
                assert False


    class TestCheckingBody(TestChecker):

        def test_check_request_body_ok(self):
            request = Request('POST', 'http://example.com/query/?q=test&fmt=json', {'Host': 'example.com', 'Content-Type':'application/x-www-form-urlencoded'}, 'oauth_token=ACCESS_TOKEN')
            token = self.request_handler.check_request(request=request)
            assert token.client.client_id == self.client.client_id
            assert token.scope == 'scope'


        def test_check_request_body_fails_if_wrong(self):
            request = Request('POST', 'http://example.com/query/?q=test&fmt=json', {'Host': 'example.com', 'Content-Type':'application/x-www-form-urlencoded'}, 'oauth_token=ANOTHER_TOKEN')
            try:
                token = self.request_handler.check_request(request=request)
            except InvalidClient:
                pass
            else:
                assert False

        def test_check_request_body_fails_if_should_have_no_body(self):
            request = Request('GET', 'http://example.com/query/?q=test&fmt=json', {'Host': 'example.com', 'Content-Type':'application/x-www-form-urlencoded'}, 'oauth_token=ACCESS_TOKEN')
            try:
                token = self.request_handler.check_request(request=request)
            except self.request_handler.AuthenticationNotFound:
                pass
            else:
                assert False

        def test_check_request_body_fails_if_wrong_content_type(self):
            request = Request('GET', 'http://example.com/query/?q=test&fmt=json', {'Host': 'example.com', 'Content-Type':'text/html'}, 'oauth_token=ACCESS_TOKEN')
            try:
                token = self.request_handler.check_request(request=request)
            except self.request_handler.AuthenticationNotFound:
                pass
            else:
                assert False

        def test_check_request_body_fails_if_no_content_type(self):
            request = Request('GET', 'http://example.com/query/?q=test&fmt=json', {'Host': 'example.com'}, 'oauth_token=ACCESS_TOKEN')
            try:
                token = self.request_handler.check_request(request=request)
            except self.request_handler.AuthenticationNotFound:
                pass
            else:
                assert False

        def test_check_request_body_fails_if_disallowed(self):
            request = Request('POST', 'http://example.com/query/?q=test&fmt=json', {'Host': 'example.com', 'Content-Type':'application/x-www-form-urlencoded'}, 'oauth_token=HEADER_TOKEN')
            try:
                token = self.request_handler.check_request(request=request)
            except self.request_handler.AuthenticationNotPermitted:
                pass
            else:
                assert False


    class TestCheckingUri(TestChecker):

        def test_check_request_uri_ok(self):
            request = Request('GET', 'http://example.com/query/?q=test&fmt=json&oauth_token=ACCESS_TOKEN', {'Host': 'example.com'}, '')
            token = self.request_handler.check_request(request=request)
            assert token.client.client_id == self.client.client_id
            assert token.scope == 'scope'


        def test_check_request_body_fails_if_wrong(self):
            request = Request('GET', 'http://example.com/query/?q=test&fmt=json&oauth_token=ANOTHER_TOKEN', {'Host': 'example.com'}, '')
            try:
                token = self.request_handler.check_request(request=request)
            except InvalidClient:
                pass
            else:
                assert False

        def test_check_request_body_fails_if_disallowed(self):
            request = Request('GET', 'http://example.com/query/?q=test&fmt=json&oauth_token=HEADER_TOKEN', {'Host': 'example.com'}, '')
            try:
                token = self.request_handler.check_request(request=request)
            except self.request_handler.AuthenticationNotPermitted:
                pass
            else:
                assert False

    return {
        'TestBasicChecks': TestBasicChecks,
        'TestCheckingHeader':TestCheckingHeader,
        'TestCheckingBody': TestCheckingBody,
        'TestCheckingUri':TestCheckingUri
        }


def constructor_for_mac_checks(token_store, client_store):
    class TestChecker(object):

        def setUp(self):
            self.token_store = token_store
            self.client_store = client_store

            self.client = self.client_store.make_client(SimpleClient('client_id', 'client_secret'))
            self.access_token_sha_1 = AccessToken(self.client, 'scope', 'mac', 3600, 'ACCESS_TOKEN', None, None, secret='ACCESS_TOKEN_SECRET', algorithm='hmac-sha-1')
            self.access_token_sha_256 = AccessToken(self.client, 'scope', 'mac', 3600, 'ACCESS_TOKEN_256', None, None, secret='ACCESS_TOKEN_SECRET_256', algorithm='hmac-sha-256')
            self.token_store.save_access_token(self.access_token_sha_1)
            self.token_store.save_access_token(self.access_token_sha_256)
            self.policy = LowSecurityPolicy()
            self.request_handler = RequestHandler(policy=self.policy, token_store=self.token_store, allowed_token_types=('mac',))

        def tearDown(self):
            return self.client_store.delete_client(self.client)


    class TestBasicChecker(TestChecker):
        def test_check_request_fails_if_auth_type_wrong(self):
            request = Request('GET', 'http://example.com/query/?q=test&fmt=json', {'Host': 'example.com', 'Authorization':'MAC_MISSPELT token="ACCESS_TOKEN"'}, '')
            try:
                token = self.request_handler.check_request(request=request)
            except self.request_handler.AuthenticationNotFound:
                pass
            else:
                assert False

        def test_check_request_fails_if_auth_absent(self):
            request = Request('GET', 'http://example.com/query/?q=test&fmt=json', {'Host': 'example.com'}, '')
            try:
                token = self.request_handler.check_request(request=request)
            except self.request_handler.AuthenticationNotFound:
                pass
            else:
                assert False

    class TestMacChecker(TestChecker):

        def test_check_request_header_ok(self):
            request = Request('GET', 'http://example.com/query/?q=test&fmt=json', {'Host': 'example.com', 'Authorization':'MAC token="ACCESS_TOKEN" timestamp="1234567890" nonce="nonce1" signature="L7CJk1NFQd7Lgay/WU6JL9MKbLI="'}, '')
            token = self.request_handler.check_request(request=request)
            assert token.client.client_id == self.client.client_id
            assert token.scope == 'scope'

        def test_check_request_header_ok_params_out_of_order(self):
            request = Request('GET', 'http://example.com/query/?q=test&fmt=json', {'Host': 'example.com', 'Authorization':'MAC timestamp="1234567890" nonce="nonce2" token="ACCESS_TOKEN" signature="r3jBcuyprmEJqWS2HIJ5GbT+L6E="'}, '')
            token = self.request_handler.check_request(request=request)
            assert token.client.client_id == self.client.client_id
            assert token.scope == 'scope'

        def test_check_request_header_fails_bad_timestamp(self):
            request = Request('GET', 'http://example.com/query/?q=test&fmt=json', {'Host': 'example.com', 'Authorization':'MAC token="ACCESS_TOKEN" timestamp="NOT A TIMESTAMP" nonce="nonce3" signature="ayGkNO5lTkTK0nmjYS9a2nxifEA="'}, '')
            try:
                token = self.request_handler.check_request(request=request)
            except self.request_handler.AuthenticationNotPermitted:
                pass
            else:
                assert False

        def test_check_request_header_fails_missing_param(self):
            request = Request('GET', 'http://example.com/query/?q=test&fmt=json', {'Host': 'example.com', 'Authorization':'MAC token="ACCESS_TOKEN" nonce="nonce4" signature="ayGkNO5lTkTK0nmjYS9a2nxifEA="'}, '')
            try:
                token = self.request_handler.check_request(request=request)
            except self.request_handler.AuthenticationNotPermitted:
                pass
            else:
                assert False

        def test_check_request_header_fails_bad_signature(self):
            request = Request('GET', 'http://example.com/query/?q=test&fmt=json', {'Host': 'example.com', 'Authorization':'MAC timestamp="1234567890" token="ACCESS_TOKEN" nonce="nonce5" signature="ayGkNO5lTkTK0nmjYS9a2nxifEB="'}, '')
            try:
                token = self.request_handler.check_request(request=request)
            except self.request_handler.AuthenticationNotPermitted:
                pass
            else:
                assert False

    return {
        'TestBasicChecker': TestBasicChecker,
        'TestMacChecker': TestMacChecker,
        }
