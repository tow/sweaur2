from __future__ import absolute_import

from .exceptions import InvalidScope


class Request(object):
    def __init__(self, method, uri, headers, body):
        self.method = method.upper()
        self.uri = uri
        headers = dict((k.upper(), v) for k, v in headers.items())
        self.host = headers.get('HOST', '')
        self.authorization = headers.get('AUTHORIZATION', '')
        self.headers = headers
        self.body = body


class RequestSigner(object):
    def __init__(self, access_token_obj):
        access_token_string = access_token_obj.token_string
        self.access_token_string = access_token_string

    def sign_request(self, request):
        raise TypeError("Subclass me!")


class AuthenticationException(Exception):
    status_code = None
    def __init__(self, error_msg=''):
        self.error_msg = error_msg

    def response_headers(self, *args, **kwargs):
        return {}


class RequestChecker(object):
    request_checkers = {}

    class AuthenticationBroken(AuthenticationException):
        status_code = 400

    class AuthenticationNotFound(AuthenticationException):
        status_code = 401

    class AuthenticationNotPermitted(Exception):
        status_code = 403

    def __init__(self, token_store, policy):
        self.token_store = token_store
        self.policy = policy
