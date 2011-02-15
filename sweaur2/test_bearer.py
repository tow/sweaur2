from __future__ import absolute_import

from .bearer_client import BearerHeaderRequestSigner, BearerBodyRequestSigner, BearerUriRequestSigner
from .request import Request
from .tokens import AccessToken


class TestSigningHeader(object):

    def test_bearer_header_signing_ok(self):
        access_token = AccessToken(None, '', 'MAC', None, 'ACCESS_TOKEN', None, None, header=True)
        signer = BearerHeaderRequestSigner(access_token)
        request = Request('GET', 'http://example.com/query/?q=test&fmt=json', {'Host': 'example.com'}, '')
        assert signer.sign_request(request).headers['AUTHORIZATION'] == 'Bearer ACCESS_TOKEN'

    def test_bearer_header_signing_auth_header_already(self):
        access_token = AccessToken(None, '', 'MAC', None, 'ACCESS_TOKEN', None, None, header=True)
        signer = BearerHeaderRequestSigner(access_token)
        request = Request('GET', 'http://example.com/query/?q=test&fmt=json', {'Host': 'example.com', 'Authorization': 'Bearer ANOTHER_TOKEN'}, '')
        try:
            signer.sign_request(request)
        except ValueError:
            pass
        else:
            assert False


class TestSigningBody(object):

    def test_bearer_body_signing_ok_empty_body(self):
        access_token = AccessToken(None, '', 'MAC', None, 'ACCESS_TOKEN', None, None, header=True)
        signer = BearerBodyRequestSigner(access_token)
        request = Request('POST', 'http://example.com/query/?q=test&fmt=json', {'Host': 'example.com', 'Content-Type':'x-www-form-urlencoded'}, '')
        assert signer.sign_request(request).body == 'oauth_token=ACCESS_TOKEN'

    def test_bearer_body_signing_ok_existing_body(self):
        access_token = AccessToken(None, '', 'MAC', None, 'ACCESS_TOKEN', None, None, body=True)
        signer = BearerBodyRequestSigner(access_token)
        request = Request('POST', 'http://example.com/query/?q=test&fmt=json', {'Host': 'example.com', 'Content-Type':'x-www-form-urlencoded'}, 'param=value')
        assert signer.sign_request(request).body == 'param=value&oauth_token=ACCESS_TOKEN'

    def test_bearer_body_signing_wrong_method(self):
        access_token = AccessToken(None, '', 'MAC', None, 'ACCESS_TOKEN', None, None, body=True)
        signer = BearerBodyRequestSigner(access_token)
        request = Request('GET', 'http://example.com/query/?q=test&fmt=json', {'Host': 'example.com', 'Content-Type':'x-www-form-urlencoded'}, '')
        try:
            signer.sign_request(request)
        except ValueError:
            pass
        else:
            assert False

    def test_bearer_body_signing_wrong_content_type(self):
        access_token = AccessToken(None, '', 'MAC', None, 'ACCESS_TOKEN', None, None, body=True)
        signer = BearerBodyRequestSigner(access_token)
        request = Request('POST', 'http://example.com/query/?q=test&fmt=json', {'Host': 'example.com', 'Content-Type':'text/plain'}, '')
        try:
            signer.sign_request(request)
        except ValueError:
            pass
        else:
            assert False

    def test_bearer_body_signing_no_content_type(self):
        access_token = AccessToken(None, '', 'MAC', None, 'ACCESS_TOKEN', None, None, body=True)
        signer = BearerBodyRequestSigner(access_token)
        request = Request('POST', 'http://example.com/query/?q=test&fmt=json', {'Host': 'example.com'}, '')
        try:
            signer.sign_request(request)
        except ValueError:
            pass
        else:
            assert False

    def test_bearer_body_signing_already_signed(self):
        access_token = AccessToken(None, '', 'MAC', None, 'ACCESS_TOKEN', None, None, body=True)
        signer = BearerBodyRequestSigner(access_token)
        request = Request('POST', 'http://example.com/query/?q=test&fmt=json', {'Host': 'example.com'}, 'oauth_token=ANOTHER_TOKEN')
        try:
            signer.sign_request(request)
        except ValueError:
            pass
        else:
            assert False


class TestSigningUri(object):

    def test_bearer_uri_signing_ok_empty_params(self):
        access_token = AccessToken(None, '', 'MAC', None, 'ACCESS_TOKEN', None, None, uri=True)
        signer = BearerUriRequestSigner(access_token)
        request = Request('GET', 'http://example.com/query/', {'Host': 'example.com', 'Content-Type':'x-www-form-urlencoded'}, '')
        assert signer.sign_request(request).uri == 'http://example.com/query/?oauth_token=ACCESS_TOKEN'

    def test_bearer_uri_signing_ok_existing_params(self):
        access_token = AccessToken(None, '', 'MAC', None, 'ACCESS_TOKEN', None, None, uri=True)
        signer = BearerUriRequestSigner(access_token)
        request = Request('GET', 'http://example.com/query/?q=test&fmt=json', {'Host': 'example.com', 'Content-Type':'x-www-form-urlencoded'}, '')
        assert signer.sign_request(request).uri == 'http://example.com/query/?q=test&fmt=json&oauth_token=ACCESS_TOKEN'

    def test_bearer_uri_signing_already_signed(self):
        access_token = AccessToken(None, '', 'MAC', None, 'ACCESS_TOKEN', None, None, uri=True)
        signer = BearerUriRequestSigner(access_token)
        request = Request('GET', 'http://example.com/query/?q=test&fmt=json&oauth_token=ANOTHER_TOKEN', {'Host': 'example.com'}, '')
        try:
            signer.sign_request(request)
        except ValueError:
            pass
        else:
            assert False
