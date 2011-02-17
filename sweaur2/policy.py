from __future__ import absolute_import

from .tokens import AccessToken, RefreshToken
from .token_types import TokenType, MACTokenType, token_type_map
from .utils import random_string


class Policy(object):

    # For ACCESS TOKEN
    def token_type(self, client, scope):
        """What token type should we issue?
        Expected result: BearerTokenType or MACTokenType."""
        raise TypeError("Subclass me!")

    # For ACCESS TOKEN
    def expires_in(self, client, scope):
        """What is the expiry time (in seconds) of the access token?
        None means no expiry."""
        raise TypeError("Subclass me!")

    # For ACCESS TOKEN
    def refresh_token(self, client, scope):
        """Should we issue a refresh token?
        True/False"""
        raise TypeError("Subclass me!")

    # For ACCESS TOKEN
    def scope_for_access_token(self, client, scope):
        """Is this client allowed to request this scope on an access token?
        True/False"""
        raise TypeError("Subclass me!")

    # For ACCESS TOKEN
    def new_access_token_string(self, client, scope):
        """Return a string suitable for use as a new access token.
        You'll want to do something like this, but incorporate
        a uniqueness check against existing tokens"""
        token_type = self.token_type(client, scope)
        token_length = 16
        allowed_token_chars = token_type_map[token_type].allowed_token_chars
        return random_string(token_length, allowed_token_chars)

    # For ACCESS TOKEN
    def new_refresh_token_string(self, client, scope):
        """Return a string suitable for use as a new refresh token.
        You'll want to do something like this, but incorporate
        a uniqueness check against existing tokens"""
        token_length = 16
        allowed_token_chars = TokenType.allowed_token_chars
        return random_string(token_length, allowed_token_chars)

    # For REQUEST
    def check_scope_for_request(self, client, scope, request):
        """Is the given client permitted to make this request under this scope?
        True/False"""
        raise TypeError("Subclass me!")

# For Bearer Tokens
    # For ACCESS_TOKEN
    def body_auth_ok(self, client, scope):
        """Should the client be allowed to use body auth 
        to authenticate with this token?
        True/False"""
        raise TypeError("Subclass me!")

    # For ACCESS_TOKEN
    def uri_auth_ok(self, client, scope):
        """Should the client be allowed to use body auth 
        to authenticate with this token?
        True/False"""
        raise TypeError("Subclass me!")

# For MAC Tokens

    # For ACCESS TOKEN
    def new_access_token_secret(self, client, scope):
        """Return a string suitable for use as a new refresh token"""
        token_length = 16
        allowed_token_chars = MACTokenType.allowed_token_chars
        return random_string(token_length, allowed_token_chars)

    # For ACCESS_TOKEN
    def algorithm(self, client, scope):
        """Which algorithm should be used for an access token
        with this client and scope?
        hmac-sha-1/hmac-sha-256"""
        raise TypeError("Subclass me!")        

    # For REQUEST_TOKEN
    def check_timestamp(self, client, scope, request, timestamp):
        """Is a request with this timestamp ok?"""
        raise TypeError("Subclass me!")

    # For REQUEST_TOKEN
    def check_nonce(self, client, scope, request, nonce):
        """Is a request with this nonce ok?"""
        raise TypeError("Subclass me!")


class LowSecurityPolicy(Policy):
    """Recommended only for testing out APIs"""
    def token_type(self, client, scope):
        return 'bearer'

    def expires_in(self, client, scope):
        return None

    def refresh_token(self, client, scope):
        return False

    def scope_for_access_token(self, client, scope):
        return True

    def body_auth_ok(self, client, scope):
        return True

    def uri_auth_ok(self, client, scope):
        return True

    def check_scope_for_request(self, client, scope, request):
        return True

    # These next two only necessary if token_type has been overridden
    def check_timestamp(self, client, scope, request, timestamp):
        return True

    def check_nonce(self, client, scope, request, nonce):
        return True


class DefaultPolicy(Policy):
    """Reasonably secure settings, will need
    adapting for specifics of a given site."""
    def token_type(self, client, scope):
        return 'mac'

    def expires_in(self, client, scope):
        return 3600

    def refresh_token(self, client, scope):
        return True

    def scope_for_access_token(self, client, scope):
        return True

    def check_scope_for_request(self, client, scope, request):
        # You probably want to check your site's permission
        # framework / policy here.
        raise NotImplemented

    def algorithm(self, client, scope):
        return 'hmac-sha-256'

    def check_timestamp(self, client, scope, request, timestamp):
        return iabs(timestamp - time.time()) < 3000

    def check_nonce(self, client, scope, request, nonce):
        # You should check in your backend somewhere that
        # this nonce hasn't been used recently.
        raise NotImplemented
