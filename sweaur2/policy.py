from __future__ import absolute_import

from .tokens import AccessToken, RefreshToken
from .token_types import BearerTokenType, MACTokenType


class Policy(object):
    def token_type(self, client, scope):
        """What token type should we issue?
        Expected result: BearerTokenType or MACTokenType."""
        raise TypeError("Subclass me!")

    def expiry_time(self, client, scope):
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

    def check_scope(self, client, scope):
        """Is the given client permitted this scope?
        True/False"""
        raise TypeError("Subclass me!")

    def new_access_token(self, client, scope):
        token_type = client.token_type(scope)
        expiry_time = self.expiry_time(client, scope)
        if self.refresh_token(client, scope):
            refresh_token = RefreshToken(self, scope)
        else:
            refresh_token = None
        token_length = self.token_length(client, scope)
        return AccessToken(client, scope, token_type, expiry_time, token_length, refresh_token)

    def refresh_access_token(self, client, scope, old_refresh_token):
        token_type = self.client.token_type
        expiry_time = self.expiry_time(client, scope)
        if self.refresh_token(client, scope):
            new_refresh_token = RefreshToken(self, scope)
        else:
            new_refresh_token = None
        token_length = self.token_length(client, scope)
        return AccessToken(client, scope, token_type, expiry_time, token_length, new_refresh_token, old_refresh_token)
        

class LowSecurityPolicy(Policy):
    """Recommended only for testing out APIs"""
    def token_type(self, client, scope):
        return BearerTokenType

    def expiry_time(self, client, scope):
        return None

    def refresh_token(self, client, scope):
        return False

    def token_length(self, client, scope):
        return 8

    def check_scope(self, client, scope):
        return True

class DefaultPolicy(Policy):
    """Reasonably secure settings"""
    def token_type(self, client, scope):
        return MACTokenType

    def expiry_time(self, client, scope):
        return 3600

    def refresh_token(self, client, scope):
        return True

    def token_length(self, client, scope):
        return 32

    def check_scope(self, client, scope):
        return True
