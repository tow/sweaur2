from __future__ import absolute_import


class OAuth2Error(Exception):
    def __init__(self, error_description='', error_uri=''):
        self.error_description = error_description
        self.error_uri = error_uri

    def __unicode__(self):
        d = {'error': self.error}
        if self.error_description:
            d['error_description'] = self.error_description
        if self.error_uri:
            d['error_uri'] = self.error_uri


class InvalidRequest(OAuth2Error):
    error = "invalid_request"

class InvalidClient(OAuth2Error):
    error = "invalid_client"

class InvalidGrant(OAuth2Error):
    error = "invalid_client"

class UnauthorizedClient(OAuth2Error):
    error = "unauthorized_client"

class UnsupportedGrantType(OAuth2Error):
    error = "unsupported_grant_type"

class InvalidScope(OAuth2Error):
    error = "invalid_scope"
