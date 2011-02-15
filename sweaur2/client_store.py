from __future__ import absolute_import


class ClientStore(object):
    class NoSuchClient(Exception):
        pass

    def get_client(self, client_id, client_secret):
        raise TypeError("Subclass me!")

    # These are only necessary for tests
    def make_client(client):
        raise TypeError("Subclass me!")

    def delete_client(client):
        raise TypeError("Subclass me!")
