from __future__ import absolute_import


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


class RequestChecker(object):
    class AuthenticationNotFound(Exception):
        pass

    class AuthenticationNotPermitted(Exception):
        pass

    def __init__(self, token_store, policy):
        self.token_store = token_store
        self.policy = policy


class OAuth2Connection(object):
    def __init__(self, token_object, signing_params=None):
        if signing_params is None:
            signing_params = {}
        self.signer = self.token_object.token_type.signer_class(token_object, **signing_params)
        
    def get_authentication_header(self, method, uri, headers, body):
        return self.signer.make_authorization_header(Request(method, uri, headers, body))
