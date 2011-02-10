from __future__ import absolute_import

import random


class TokenType(object):
    allowed_chars = []

    @classmethod
    def random_string(cls, length):
        return ''.join([random.choice(cls.allowed_chars) for i in range(l)])

    def new_token(self):
        raise TypeError("Subclass me!")

class BearerTokenType(TokenType):
    allowed_chars = [chr(a) for a in range(33,127)]

    @classmethod
    def new_token(cls, token_length):
        return self.random_string(token_length)

    # check ...

class MACTokenType(TokenType):
    pass
