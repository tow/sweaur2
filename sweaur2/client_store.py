from __future__ import absolute_import


class ClientStore(object):
    class NoSuchClient(Exception):
        pass
