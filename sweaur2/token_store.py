from __future__ import absolute_import


class TokenStore(object):
    class NoSuchToken(Exception):
        pass

    def save_access_token(self, token):
        raise TypeError("Subclass me!")

    def save_refresh_token(self, token):
        raise TypeError("Subclass me!")

    def get_access_token(self, token_string):
        raise TypeError("Subclass me!")    

    def get_refresh_token(self, token_string):
        raise TypeError("Subclass me!")    
