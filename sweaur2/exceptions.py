from __future__ import absolute_import


class OAuth2Error(Exception):
    valid_errors = ['invalid_request', 'invalid_client', 'invalid_grant', 'unauthorized_client', 'unsupported_grant_type', 'invalid_scope']
    def __init__(self, error, error_description='', error_uri=''):
        if error not in self.valid_errors:
            raise ValueError("%s is not a valid OAuth2 error" % error)
        self.error = error
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
    def __init__(self, error_description='', error_uri=''):
        self.error_description = error_description
        self.error_uri = error_uri
        super(InvalidRequest, self).__init__()

class InvalidClient(OAuth2Error):
    error = "invalid_client"
    def __init__(self, error_description='', error_uri=''):
        self.error_description = error_description
        self.error_uri = error_uri
        super(InvalidClient, self).__init__()

class InvalidGrant(OAuth2Error):
    error = "invalid_client"
    def __init__(self, error_description='', error_uri=''):
        self.error_description = error_description
        self.error_uri = error_uri
        super(InvalidGrant, self).__init__()

class UnauthorizedClient(OAuth2Error):
    error = "unauthorized_client"
    def __init__(self, error_description='', error_uri=''):
        self.error_description = error_description
        self.error_uri = error_uri
        super(UnauthorizedClient, self).__init__()

class UnsupportedGrantType(OAuth2Error):
    error = "unsupported_grant_type"
    def __init__(self, error_description='', error_uri=''):
        self.error_description = error_description
        self.error_uri = error_uri
        super(UnsupportedGrantType, self).__init__()

class InvalidScope(OAuth2Error):
    error = "invalid_scope"
    def __init__(self, error_description='', error_uri=''):
        self.error_description = error_description
        self.error_uri = error_uri
        super(InvalidScope, self).__init__()
