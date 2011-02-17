from __future__ import absolute_import

from .utils import random_string


class TokenType(object):
    allowed_token_chars = ''.join(chr(i) for i in range(32, 127))


class BearerTokenType(TokenType):
    extra_parameter_defaults = {
        'body': True,
        'uri': True,
    }

    @classmethod
    def new_extra_parameters(cls, policy, client, scope):
        return {
            'body_auth_ok': policy.body_auth_ok(client, scope),
            'uri_auth_ok': policy.uri_auth_ok(client, scope),
        }


class MACTokenType(TokenType):
    allowed_token_chars = ''.join(chr(i) for i in range(32, 127) if i not in (34, 92))
    allowed_secret_chars = allowed_token_chars

    extra_parameter_defaults = {
        'algorithm': 'hma-sha-256',
        'secret': None,
    }

    supported_algorithms = [
         'hmac-sha-1',
         'hmac-sha-256',
    ]

    @classmethod
    def new_extra_parameters(cls, policy, client, scope):
        return {
            'algorithm': policy.algorithm(client, scope),
            'secret': policy.new_access_token_secret(client, scope),
        }


token_type_map = {
   'bearer': BearerTokenType,
   'mac': MACTokenType,
}
