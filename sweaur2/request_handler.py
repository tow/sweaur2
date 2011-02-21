from __future__ import absolute_import

from .bearer_server import BearerRequestChecker
from .exceptions import InvalidRequest
from .mac_server import MACRequestChecker
from .request import RequestChecker
from .utils import quoted_string


registered_request_checkers = {
    'bearer':BearerRequestChecker,
    'mac':MACRequestChecker,
}


class RequestHandler(object):
    AuthenticationNotPermitted = RequestChecker.AuthenticationNotPermitted

    def __init__(self, policy, token_store, allowed_token_types=None):
        class AuthenticationNotFound(RequestChecker.AuthenticationNotFound):
            def response_headers(self, realm=None, *args, **kwargs):
                auth_headers = []
                for token_type in allowed_token_types:
                    auth_header = registered_request_checkers[token_type].auth_type
                    if realm:
                        auth_header += ' realm="%s"' % quoted_string(realm)
                    if self.error_msg:
                        auth_header += ' error="%s"' % quoted_string(self.error_msg)
                    auth_headers.append(auth_header)
                return {'WWW-Authenticate': ', '.join(auth_headers)}

        self.AuthenticationNotFound = AuthenticationNotFound
        self.policy = policy
        self.token_store = token_store
        if allowed_token_types is None:
            allowed_token_types = ('bearer', 'mac')
        self.request_checkers = [
            registered_request_checkers[k](policy=policy, token_store=token_store)
            for k in allowed_token_types]

    def check_request(self, request):
        token = None
        for request_checker in self.request_checkers:
            try:
                token = request_checker.do_request_check(request)
            except request_checker.AuthenticationNotFound:
                pass
            except InvalidRequest:
                raise self.AuthenticationNotPermitted()
        if not token:
            raise self.AuthenticationNotFound()
        if not self.policy.check_scope_for_request(token.client, token.scope, request):
            raise InvalidScope("You can't make that request under the scope of this access token")
        return token
