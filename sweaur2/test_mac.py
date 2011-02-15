from __future__ import absolute_import

from .mac_client import Hmac_Sha_1_RequestSigner, Hmac_Sha_256_RequestSigner
from .request import Request
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
        access_token = AccessToken(None, '', 'MAC', None, 'ACCESS_TOKEN', None, None, secret_token_string='ACCESS_TOKEN_SECRET', algorithm='hmac-sha-1')
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
        access_token = AccessToken(None, '', 'MAC', None, 'ACCESS_TOKEN', None, None, secret_token_string='ACCESS_TOKEN_SECRET', algorithm='hmac-sha-1')
        signer = Hmac_Sha_1_RequestSigner(access_token, self.timestamp_generator, self.nonce_generator)
        request = Request('GET', 'http://example.com/query/?q=test&fmt=json', {'Host': 'example.com'}, '')
        assert signer.sign_request(request).headers['AUTHORIZATION'] == \
'MAC token="ACCESS_TOKEN" timestamp="1234567890" nonce="nonce" signature="ayGkNO5lTkTK0nmjYS9a2nxifEA="'

    def test_hmac_sha_256_signing(self):
        access_token = AccessToken(None, '', 'MAC', None, 'ACCESS_TOKEN', None, None, secret_token_string='ACCESS_TOKEN_SECRET', algorithm='hmac-sha-256')
        signer = Hmac_Sha_256_RequestSigner(access_token, self.timestamp_generator, self.nonce_generator)
        request = Request('GET', 'http://example.com/query/?q=test&fmt=json', {'Host': 'example.com'}, '')
        assert signer.sign_request(request).headers['AUTHORIZATION'] == \
'MAC token="ACCESS_TOKEN" timestamp="1234567890" nonce="nonce" signature="lO/dtdfkwLVKnD0BzaxUyDTk8poI+vpxxh535VRF2xA="'
