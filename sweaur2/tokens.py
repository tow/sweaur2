from __future__ import absolute_import

from .token_types import TokenType, token_type_map
from .utils import normalize_http_header_value


class Token(object):
    @classmethod
    def parse_scope_string(cls, scope_string):
        scope_string = normalize_http_header_value(scope_string)
        if scope_string:
            return set(scope_string.split(' '))
        else:
            return set()

    def check_scope(self, scope_string_1, scope_string_2):
        """Are all the scopes in scope_string_1 within the scopes in scope_string_2?"""
        return not bool(self.parse_scope_string(scope_string_1) - self.parse_scope_string(scope_string_2))


class AccessToken(Token):
    def __init__(self, client, scope, token_type, expires_in, token_string, old_refresh_token_string, new_refresh_token_string, **extra_params):
        self.client = client
        self.scope = scope
        self.token_type = token_type
        self.token_type_class = token_type_map[token_type]
        self.expires_in = expires_in
        self.token_string = token_string
        self.old_refresh_token_string = old_refresh_token_string
        self.new_refresh_token_string = new_refresh_token_string
        for k, v in extra_params.items():
            setattr(self, k, v)

    @classmethod
    def create(cls, client, scope, token_type, expires_in, token_length, old_refresh_token_string, new_refresh_token_string):
        access_token = cls(client, scope, token_type, expires_in, '', old_refresh_token_string, new_refresh_token_string)
        access_token.token_string = access_token.token_type_class.new_token_string(token_length)
        return access_token

    def as_dict(self):
        d = {"access_token": self.token,
             "token_type": token_type.name}
        if self.expires_in:
            d["expires_in"] = self.expires_in
        if self.old_refresh_token:
            d["refresh_token"] = self.old_refresh_token.token


class RefreshToken(Token):
    def __init__(self, client, scope, token_string, old_access_token_string, new_access_token_string):
        self.client = client
        self.scope = scope
        self.token_string = token_string
        self.old_access_token_string = old_access_token_string
        self.new_access_token_string = new_access_token_string

    @classmethod
    def create(cls, client, scope, token_length):
         return cls(client, scope, TokenType.new_token_string(token_length), None, None)

    def check_sub_scope(self, scope):
        return self.check_scope(scope, self.scope)
