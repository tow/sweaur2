from __future__ import absolute_import

from .mac_client import RequestSigner, Hmac_Sha_1_RequestSigner, Hmac_Sha_256_RequestSigner
from .request import Request

class TestSigning(object):
    timestamp = '123456789'
    nonce = 'nonce'

    @classmethod
    def timestamp_generator(cls):
        return cls.timestamp

    @classmethod
    def nonce_generator(cls):
        return cls.nonce

    def test_normalized_request_string(self):
        signer = RequestSigner('ACCESS_TOKEN', 'ACCESS_TOKEN_SECRET', self.timestamp_generator, self.nonce_generator)
        request = Request('GET', 'http://example.com/query/?q=test&fmt=json', {'Host': 'example.com'}, '')
        assert signer.normalized_request_string(request, '123456789', 'nonce') == """\
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
