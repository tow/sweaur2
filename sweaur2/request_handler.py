from __future__ import absolute_import

from .bearer_server import BearerRequestChecker
from .mac_server import MACRequestChecker
from .request import RequestChecker


registered_request_checkers = {
    'bearer':BearerRequestChecker,
    'mac':MACRequestChecker,
}


class RequestHandler(object):
    AuthenticationNotFound = RequestChecker.AuthenticationNotFound
    AuthenticationNotPermitted = RequestChecker.AuthenticationNotPermitted

    def __init__(self, policy, token_store, allowed_token_types=None):
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
        if not token:
            raise request_checker.AuthenticationNotFound
        if not self.policy.check_scope_for_request(token.client, token.scope, request):
            raise InvalidScope("You can't make that request under the scope of this access token")
        return token
