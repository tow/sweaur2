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


class ClientStoreSimpleDict(ClientStore):
    def __init__(self):
        self.clients = {}

    def make_client(self, client, active=True):
        self.clients[(client.client_id, client.client_secret)] = client
        return client

    def get_client(self, client_id, client_secret):
        try:
            return self.clients[(client_id, client_secret)]
        except KeyError:
            raise self.NoSuchClient()

    def delete_client(self, client):
        del self.clients[(client.client_id, client.client_secret)]
