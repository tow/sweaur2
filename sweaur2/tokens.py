from __future__ import absolute_import

import re


class Token(object):
    lws_re = re.compile('[ \t\n]+')

    @classmethod
    def parse_scope_string(scope_string):
        scopes = set(self.lws_re.sub(' ', scope_string.strip()).split(' '))

    def check_scope(self, scope_string_1, scope_string_2):
        """Are all the scopes in scope_string_1 within the scopes in scope_string_2?"""
        return not bool(self.parse_scope_string(scope_string_1) - self.parse_scope_string(scope_string_2))


class AccessToken(Token):
    def __init__(self, client, scope, token_type, expiry_time, token_length, new_refresh_token, old_refresh_token):
        self.client = client
        self.scope = scope
        self.token_type = token_type
        self.expiry_time = expiry_time
        self.token_string = token_type.new_token_string(token_length)
        self.new_refresh_token = new_refresh_token
        self.old_refresh_token = old_refresh_token

    def as_dict(self):
        d = {"access_token": self.token,
             "token_type": token_type.name}
        if self.expiry_time:
            d["expires_in"] = self.expiry_time
        if self.old_refresh_token:
            d["refresh_token"] = self.old_refresh_token.token


class RefreshToken(Token):
    def __init__(self, client, scope, token_type, access_token):
        self.client = client
        self.scope = scope
        self.token_type = token_type
        self.access_token = access_token

    def check_scope(self, scope):
        return self.check_scope(self.scope, scope)
