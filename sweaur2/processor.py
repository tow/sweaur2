from __future__ import absolute_import

from .exceptions import InvalidRequest, InvalidClient, InvalidGrant, UnauthorizedClient, UnsupportedGrantType, InvalidScope

class OAuth2Processor(object):
    def __init__(self, client_store, token_store, policy):
        self.client_store = client_store
        self.token_store = token_store
        self.policy = policy

    def oauth2_token_endpoint(self, **kwargs):
        try:
            grant_type = kwargs.pop('grant_type')
        except KeyError:
            raise InvalidRequest("No grant_type specified")
        try:
            oauth2_flow = getattr(self, 'oauth2_flow_%s' % grant_type)
        except AttributeError:
            raise UnsupportedGrantType()
        return oauth2_flow(**kwargs)

    def oauth2_flow_authorization_code(**kwargs):
        raise UnsupportedGrantType()

    def oauth2_flow_password(**kwargs):
        raise UnsupportedGrantType()

    def oauth2_flow_client_credentials(self, **kwargs):
        try:
            client_id = kwargs['client_id']
        except KeyError:
            raise InvalidRequest("No client_id specified")
        try:
            client_secret = kwargs['client_secret']
        except KeyError:
            raise InvalidRequest("No client_secret specified")
        try:
            client = self.client_store.get_client(client_id, client_secret)
        except self.client_store.InvalidClient:
            raise InvalidClient()
        scope = kwargs.get('scope')
        if not self.policy.check_scope(client, scope):
            raise InvalidScope()
        return self.policy.new_access_token(client, scope)

    def oauth2_flow_refresh_token(self, **kwargs):
        try:
            refresh_token = kwargs['refresh_token']
        except KeyError:
            raise InvalidRequest('No refresh_token specified')
        try:
            refresh_token_obj = TokenStore.get_refresh_token(refresh_token)
        except TokenStore.InvalidToken:
            raise InvalidClient()
        client = refresh_token_obj.client
        scope = kwargs.get('scope')
        if not self.policy.check_scope(client, scope) or refresh_token_obj.check_scope(scope):
            raise InvalidScope()
        return self.policy.refresh_access_token(client, scope, refresh_token_obj)
