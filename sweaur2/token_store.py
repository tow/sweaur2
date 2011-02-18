from __future__ import absolute_import


class TokenStore(object):
    class NoSuchToken(Exception):
        pass

    def save_access_token(self, token):
        raise TypeError("Subclass me!")

    def save_refresh_token(self, token):
        raise TypeError("Subclass me!")

    def get_access_token(self, token_string, token_type):
        raise TypeError("Subclass me!")    

    def get_refresh_token(self, token_string):
        raise TypeError("Subclass me!")    

    def check_nonce(self, nonce, timestamp, token):
        raise TypeError("Subclass me!")    


class TokenStoreSimpleDict(TokenStore):
    def __init__(self):
        self.access_tokens = {}
        self.refresh_tokens = {}
        self.nonce_sense = set() # Phil Collins

    def save_access_token(self, token):
        self.access_tokens[token.token_string] = token

    def save_refresh_token(self, token):
        self.refresh_tokens[token.token_string] = token

    def get_refresh_token(self, refresh_token_string):
        try:
            return self.refresh_tokens[refresh_token_string]
        except KeyError:
            raise self.NoSuchToken()

    def get_access_token(self, access_token_string, token_type):
        try:
            return self.access_tokens[access_token_string]
        except KeyError:
            raise self.NoSuchToken()

    def check_nonce(self, nonce, timestamp, token):
        if nonce in self.nonce_sense:
            return False
        self.nonce_sense.add((nonce, timestamp, token))
        return True
