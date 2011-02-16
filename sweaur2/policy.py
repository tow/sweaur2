from __future__ import absolute_import

from .tokens import AccessToken, RefreshToken
from .token_types import BearerTokenType, MACTokenType


class Policy(object):
    def token_type(self, client, scope):
        """What token type should we issue?
        Expected result: BearerTokenType or MACTokenType."""
        raise TypeError("Subclass me!")

    def expires_in(self, client, scope):
        """What is the expiry time (in seconds) of the access token?
        None means no expiry."""
        raise TypeError("Subclass me!")

    def refresh_token(self, client, scope):
        """Should we issue a refresh token?
        True/False"""
        raise TypeError("Subclass me!")

    def token_length(self, client, scope):
        """How many characters long should the token be?"""
        raise TypeError("Subclass me!")

    def check_scope(self, client, scope, request):
        """Is the given client permitted this scope of action on this request?
        True/False"""
        raise TypeError("Subclass me!")


class LowSecurityPolicy(Policy):
    """Recommended only for testing out APIs"""
    def token_type(self, client, scope):
        return 'bearer'

    def expires_in(self, client, scope):
        return None

    def refresh_token(self, client, scope):
        return False

    def token_length(self, client, scope):
        return 8

    def check_scope(self, client, scope, request):
        return True


class DefaultPolicy(Policy):
    """Reasonably secure settings"""
    def token_type(self, client, scope):
        return 'mac'

    def expires_in(self, client, scope):
        return 3600

    def refresh_token(self, client, scope):
        return True

    def token_length(self, client, scope):
        return 32

    def check_scope(self, client, scope, request):
        return True
