from __future__ import absolute_import

from .utils import random_string


class TokenType(object):
    def new_token_string(self):
        raise TypeError("Subclass me!")

class BearerTokenType(TokenType):
    @classmethod
    def new_token_string(cls, token_length):
        return random_string(token_length)

    # check ...

class MACTokenType(TokenType):
    pass
