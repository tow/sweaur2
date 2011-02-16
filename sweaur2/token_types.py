from __future__ import absolute_import

from .utils import random_string


class TokenType(object):
    @classmethod
    def new_token_string(cls, token_length):
        return random_string(token_length)


class BearerTokenType(TokenType):
    pass


class MACTokenType(TokenType):
    def __init__(self, algorithm):
        try:
            self.signer_class = default_signers[algorithm]
        except KeyError:
            raise ValueError("Unknown MAC signing algorithm: %s" % algorithm)

token_type_map = {
   'bearer': BearerTokenType,
   'mac': MACTokenType,
}
