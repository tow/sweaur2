from __future__ import absolute_import

from .bearer_client import BearerHeaderRequestSigner, BearerBodyRequestSigner, BearerUriRequestSigner
from .bearer_server import BearerRequestChecker
from .exceptions import InvalidClient
from .policy import LowSecurityPolicy
from .request import Request
from .request_handler import RequestHandler
from .test_token_endpoint import TokenStoreForTest
from .tokens import AccessToken


class TestSigningHeader(object):

    def test_bearer_header_signing_ok(self):
        access_token = AccessToken(None, '', 'bearer', None, 'ACCESS_TOKEN', None, None, header=True)
        signer = BearerHeaderRequestSigner(access_token)
        request = Request('GET', 'http://example.com/query/?q=test&fmt=json', {'Host': 'example.com'}, '')
        assert signer.sign_request(request).headers['AUTHORIZATION'] == 'Bearer ACCESS_TOKEN'

    def test_bearer_header_signing_auth_header_already(self):
        access_token = AccessToken(None, '', 'bearer', None, 'ACCESS_TOKEN', None, None, header=True)
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
        access_token = AccessToken(None, '', 'bearer', None, 'ACCESS_TOKEN', None, None, header=True)
        signer = BearerBodyRequestSigner(access_token)
        request = Request('POST', 'http://example.com/query/?q=test&fmt=json', {'Host': 'example.com', 'Content-Type':'application/x-www-form-urlencoded'}, '')
        assert signer.sign_request(request).body == 'oauth_token=ACCESS_TOKEN'

    def test_bearer_body_signing_ok_existing_body(self):
        access_token = AccessToken(None, '', 'bearer', None, 'ACCESS_TOKEN', None, None, body=True)
        signer = BearerBodyRequestSigner(access_token)
        request = Request('POST', 'http://example.com/query/?q=test&fmt=json', {'Host': 'example.com', 'Content-Type':'application/x-www-form-urlencoded'}, 'param=value')
        assert signer.sign_request(request).body == 'param=value&oauth_token=ACCESS_TOKEN'

    def test_bearer_body_signing_wrong_method(self):
        access_token = AccessToken(None, '', 'bearer', None, 'ACCESS_TOKEN', None, None, body=True)
        signer = BearerBodyRequestSigner(access_token)
        request = Request('GET', 'http://example.com/query/?q=test&fmt=json', {'Host': 'example.com', 'Content-Type':'application/x-www-form-urlencoded'}, '')
        try:
            signer.sign_request(request)
        except ValueError:
            pass
        else:
            assert False

    def test_bearer_body_signing_wrong_content_type(self):
        access_token = AccessToken(None, '', 'bearer', None, 'ACCESS_TOKEN', None, None, body=True)
        signer = BearerBodyRequestSigner(access_token)
        request = Request('POST', 'http://example.com/query/?q=test&fmt=json', {'Host': 'example.com', 'Content-Type':'text/plain'}, '')
        try:
            signer.sign_request(request)
        except ValueError:
            pass
        else:
            assert False

    def test_bearer_body_signing_no_content_type(self):
        access_token = AccessToken(None, '', 'bearer', None, 'ACCESS_TOKEN', None, None, body=True)
        signer = BearerBodyRequestSigner(access_token)
        request = Request('POST', 'http://example.com/query/?q=test&fmt=json', {'Host': 'example.com'}, '')
        try:
            signer.sign_request(request)
        except ValueError:
            pass
        else:
            assert False

    def test_bearer_body_signing_already_signed(self):
        access_token = AccessToken(None, '', 'bearer', None, 'ACCESS_TOKEN', None, None, body=True)
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
        access_token = AccessToken(None, '', 'bearer', None, 'ACCESS_TOKEN', None, None, uri=True)
        signer = BearerUriRequestSigner(access_token)
        request = Request('GET', 'http://example.com/query/', {'Host': 'example.com', 'Content-Type':'application/x-www-form-urlencoded'}, '')
        assert signer.sign_request(request).uri == 'http://example.com/query/?oauth_token=ACCESS_TOKEN'

    def test_bearer_uri_signing_ok_existing_params(self):
        access_token = AccessToken(None, '', 'bearer', None, 'ACCESS_TOKEN', None, None, uri=True)
        signer = BearerUriRequestSigner(access_token)
        request = Request('GET', 'http://example.com/query/?q=test&fmt=json', {'Host': 'example.com', 'Content-Type':'application/x-www-form-urlencoded'}, '')
        assert signer.sign_request(request).uri == 'http://example.com/query/?q=test&fmt=json&oauth_token=ACCESS_TOKEN'

    def test_bearer_uri_signing_already_signed(self):
        access_token = AccessToken(None, '', 'bearer', None, 'ACCESS_TOKEN', None, None, uri=True)
        signer = BearerUriRequestSigner(access_token)
        request = Request('GET', 'http://example.com/query/?q=test&fmt=json&oauth_token=ANOTHER_TOKEN', {'Host': 'example.com'}, '')
        try:
            signer.sign_request(request)
        except ValueError:
            pass
        else:
            assert False


class TestChecker(object):

    def setUp(self):
        self.access_token_all_ok = AccessToken('client', 'scope', 'bearer', 3600, 'ACCESS_TOKEN', None, None, body=True, uri=True)
        self.access_token_only_header = AccessToken('client', 'scope', 'bearer', 3600, 'HEADER_TOKEN', None, None, body=False, uri=False)
        self.token_store = TokenStoreForTest()
        self.token_store.save_access_token(self.access_token_all_ok)
        self.token_store.save_access_token(self.access_token_only_header)
        self.policy = LowSecurityPolicy()
        self.request_handler = RequestHandler(policy=self.policy, token_store=self.token_store, allowed_token_types=('bearer',))

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
        assert token.client == 'client'
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
        assert token.client == 'client'
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
        assert token.client == 'client'
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
