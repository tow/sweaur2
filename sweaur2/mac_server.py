from __future__ import absolute_import

import base64, hashlib, hmac, re

from .exceptions import InvalidClient, InvalidRequest
from .mac_client import ascii_subset_re, timestamp_re_obj, default_signers
from .request import Request, RequestChecker
from .utils import normalize_port_number, normalize_query_parameters, parse_auth_header


class MACRequestChecker(RequestChecker):
    token_type = 'mac'
    auth_type = 'MAC'

    def __init__(self, signers=None, *args, **kwargs):
        if signers is None:
            self.signers = default_signers
        else:
            self.signers = signers
        super(MACRequestChecker, self).__init__(*args, **kwargs)

    def do_request_check(self, request):
        try:
            auth_header = request.headers['AUTHORIZATION']
        except KeyError:
            raise self.AuthenticationNotFound()
        auth_type, parameter_dict = self.check_authorization_header(auth_header)
        try:
            token = self.token_store.get_access_token(parameter_dict.pop('token'), self.token_type)
        except self.token_store.NoSuchToken:
            raise InvalidClient()
        client = token.client
        scope = token.scope
        timestamp = long(parameter_dict['timestamp'])
        if not self.policy.check_timestamp(client, scope, request, timestamp):
            raise InvalidRequest('Timestamp is too old or new')
        if not self.token_store.check_nonce(parameter_dict['nonce'], timestamp, token.token_string):
            raise InvalidRequest("I'm not going to let you use that nonce")
        if not self.check_signature(request, token, **parameter_dict):
            raise InvalidRequest("Invalid signature")
        return token

    def check_authorization_header(self, header):
        try:
            auth_type, parameter_dict = parse_auth_header(header, True)
        except ValueError:
            raise self.AuthenticationBroken()
        if auth_type != 'MAC':
            raise self.AuthenticationNotFound()
        try:
            token = parameter_dict['token']
            timestamp = parameter_dict['timestamp']
            nonce = parameter_dict['nonce']
            signature = parameter_dict['signature']
        except KeyError:
            raise self.AuthenticationNotPermitted()
        if not timestamp_re_obj.match(timestamp):
            raise self.AuthenticationNotPermitted()
        return auth_type, parameter_dict

    def check_signature(self, request, token, timestamp, nonce, signature):
        try:
            Signer = self.signers[token.algorithm]
        except KeyError:
            raise EnvironmentError("This client wants to use a signing method I don't know about: '%s'" % token.algorithm)
        signer = Signer(token)
        request_signature = signer.generate_signature(request, timestamp, nonce)
        return request_signature == signature
