from __future__ import absolute_import

from .mac_client import Hmac_Sha_1_RequestSigner, Hmac_Sha_256_RequestSigner
from .policy import LowSecurityPolicy
from .request import Request
from .request_handler import RequestHandler
from .test_runner import TokenStoreForTest
from .tokens import AccessToken


class TestSigning(object):
    timestamp = '1234567890'
    nonce = 'nonce'

    @classmethod
    def timestamp_generator(cls):
        return cls.timestamp

    @classmethod
    def nonce_generator(cls):
        return cls.nonce

    def test_normalized_request_string(self):
        access_token = AccessToken(None, '', 'mac', None, 'ACCESS_TOKEN', None, None, secret='ACCESS_TOKEN_SECRET', algorithm='hmac-sha-1')
        signer = Hmac_Sha_1_RequestSigner(access_token, self.timestamp_generator, self.nonce_generator)
        request = Request('GET', 'http://example.com/query/?q=test&fmt=json', {'Host': 'example.com'}, '')
        assert signer.normalized_request_string(request, self.timestamp, self.nonce) == """\
ACCESS_TOKEN
%s
%s

GET
example.com
80
/query/
fmt=json
q=test
""" % (self.timestamp, self.nonce)

    def test_hmac_sha_1_signing(self):
        access_token = AccessToken(None, '', 'mac', None, 'ACCESS_TOKEN', None, None, secret='ACCESS_TOKEN_SECRET', algorithm='hmac-sha-1')
        signer = Hmac_Sha_1_RequestSigner(access_token, self.timestamp_generator, self.nonce_generator)
        request = Request('GET', 'http://example.com/query/?q=test&fmt=json', {'Host': 'example.com'}, '')
        assert signer.sign_request(request).headers['AUTHORIZATION'] == \
'MAC token="ACCESS_TOKEN" timestamp="1234567890" nonce="nonce" signature="ayGkNO5lTkTK0nmjYS9a2nxifEA="'

    def test_hmac_sha_256_signing(self):
        access_token = AccessToken(None, '', 'mac', None, 'ACCESS_TOKEN', None, None, secret='ACCESS_TOKEN_SECRET', algorithm='hmac-sha-256')
        signer = Hmac_Sha_256_RequestSigner(access_token, self.timestamp_generator, self.nonce_generator)
        request = Request('GET', 'http://example.com/query/?q=test&fmt=json', {'Host': 'example.com'}, '')
        assert signer.sign_request(request).headers['AUTHORIZATION'] == \
'MAC token="ACCESS_TOKEN" timestamp="1234567890" nonce="nonce" signature="lO/dtdfkwLVKnD0BzaxUyDTk8poI+vpxxh535VRF2xA="'


class TestChecker(object):

    def setUp(self):
        self.access_token_sha_1 = AccessToken('client', 'scope', 'mac', 3600, 'ACCESS_TOKEN', None, None, secret='ACCESS_TOKEN_SECRET', algorithm='hmac-sha-1')
        self.access_token_sha_256 = AccessToken('client', 'scope', 'mac', 3600, 'ACCESS_TOKEN_256', None, None, secret='ACCESS_TOKEN_SECRET_256', algorithm='hmac-sha-256')
        self.token_store = TokenStoreForTest()
        self.token_store.save_access_token(self.access_token_sha_1)
        self.token_store.save_access_token(self.access_token_sha_256)
        self.policy = LowSecurityPolicy()
        self.request_handler = RequestHandler(policy=self.policy, token_store=self.token_store, allowed_token_types=('mac',))

    def test_check_request_fails_if_auth_type_wrong(self):
        request = Request('GET', 'http://example.com/query/?q=test&fmt=json', {'Host': 'example.com', 'Authorization':'MAC_MISSPELT token="ACCESS_TOKEN"'}, '')
        try:
            token = self.request_handler.check_request(request=request)
        except self.request_handler.AuthenticationNotFound:
            pass
        else:
            assert False

class TestMacChecker(TestChecker):
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
        request = Request('GET', 'http://example.com/query/?q=test&fmt=json', {'Host': 'example.com', 'Authorization':'MAC token="ACCESS_TOKEN" timestamp="1234567890" nonce="nonce" signature="ayGkNO5lTkTK0nmjYS9a2nxifEA="'}, '')
        token = self.request_handler.check_request(request=request)
        assert token.client == 'client'
        assert token.scope == 'scope'

    def test_check_request_header_ok_params_out_of_order(self):
        request = Request('GET', 'http://example.com/query/?q=test&fmt=json', {'Host': 'example.com', 'Authorization':'MAC timestamp="1234567890" nonce="nonce" token="ACCESS_TOKEN" signature="ayGkNO5lTkTK0nmjYS9a2nxifEA="'}, '')
        token = self.request_handler.check_request(request=request)
        assert token.client == 'client'
        assert token.scope == 'scope'

    def test_check_request_header_fails_bad_timestamp(self):
        request = Request('GET', 'http://example.com/query/?q=test&fmt=json', {'Host': 'example.com', 'Authorization':'MAC token="ACCESS_TOKEN" timestamp="NOT A TIMESTAMP" nonce="nonce" signature="ayGkNO5lTkTK0nmjYS9a2nxifEA="'}, '')
        try:
            token = self.request_handler.check_request(request=request)
        except self.request_handler.AuthenticationNotPermitted:
            pass
        else:
            assert False

    def test_check_request_header_fails_missing_param(self):
        request = Request('GET', 'http://example.com/query/?q=test&fmt=json', {'Host': 'example.com', 'Authorization':'MAC token="ACCESS_TOKEN" nonce="nonce" signature="ayGkNO5lTkTK0nmjYS9a2nxifEA="'}, '')
        try:
            token = self.request_handler.check_request(request=request)
        except self.request_handler.AuthenticationNotPermitted:
            pass
        else:
            assert False

    def test_check_request_header_fails_bad_signature(self):
        request = Request('GET', 'http://example.com/query/?q=test&fmt=json', {'Host': 'example.com', 'Authorization':'MAC token="ACCESS_TOKEN" nonce="nonce" signature="ayGkNO5lTkTK0nmjYS9a2nxifEB="'}, '')
        try:
            token = self.request_handler.check_request(request=request)
        except self.request_handler.AuthenticationNotPermitted:
            pass
        else:
            assert False
