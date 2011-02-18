from __future__ import absolute_import


class OAuth2Error(Exception):
    def __init__(self, error_description='', error_uri=''):
        self.error_description = error_description
        self.error_uri = error_uri

    def __repr__(self):
        return '%s(error="%s", error_description="%s", error_uri="%s)' % (
            self.__class__.__name__,
            self.error,
            self.error_description,
            self.uri
            )

    def as_dict(self):
        d = {'error': self.error}
        if self.error_description:
            d['error_description'] = self.error_description
        if self.error_uri:
            d['error_uri'] = self.error_uri
        return d


class InvalidRequest(OAuth2Error):
    error = "invalid_request"

class InvalidClient(OAuth2Error):
    error = "invalid_client"

class InvalidGrant(OAuth2Error):
    error = "invalid_grant"

class UnauthorizedClient(OAuth2Error):
    error = "unauthorized_client"

class UnsupportedGrantType(OAuth2Error):
    error = "unsupported_grant_type"

class InvalidScope(OAuth2Error):
    error = "invalid_scope"


class InvalidCredentials(Exception):
    def www_authenticate(self):
        pass
    # This will be used for carrying WWW-Authenticate params
    # when various flavours of auth fail.
