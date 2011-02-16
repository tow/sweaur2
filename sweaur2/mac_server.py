from __future__ import absolute_import

import base64, hashlib, hmac, re

from .mac_client import ascii_subset_re, timestamp_re_obj, default_signers
from .request import Request, RequestChecker
from .utils import normalize_port_number, normalize_query_parameters, parse_auth_header


class MACRequestChecker(RequestChecker):
    token_type = 'mac'

    def __init__(self, signers=None, *args, **kwargs):
        if signers is None:
            self.signers = default_signers
        else:
            self.signers = signers
        super(MACRequestChecker, self).__init__(*args, **kwargs)

    def do_request_check(self, request):
        try:
            auth_header = headers['AUTHORIZATION']
        except KeyError:
            raise AuthenticationNotFound()
        auth_type, parameter_dict = self.check_authorization_header(auth_header)
        try:
            token = self.token_store.get_access_token(parameter_dict['access_dict'], self.token_type)
        except self.token_store.InvalidToken:
            raise InvalidClient()
        client = token.client
        scope = token.scope
        if not self.policy.check_timestamp(client, scope, request):
            raise InvalidRequest('Timestamp is too old or new')
        if not self.policy.check_nonce(client, scope, nonce):
            raise InvalidRequest("I'm not going to let you use that nonce")
        if not check_signature(request, token, timestamp, nonce, signature):
            raise InvalidSignature()
        return token

    def check_authorization_header(self, header):
        auth_header, parameter_dict = parse_auth_header(header, True)
        if authtype != 'MAC':
            raise AuthenticationNotFound()
        try:
            access_token = parameter_dict['access_token']
            timestamp = parameter_dict['timestamp']
            nonce = parameter_dict['nonce']
            signature = parameter_dict['signature']
        except KeyError:
            raise BrokenAuthentication()
        if not timestamp_re_obj(timestamp):
            raise BrokenAuthentication()
        return auth_header, parameter_dict

    def check_signature(self, request, token, timestamp, nonce, signature):
        try:
            Signer = self.signers[token.algorithm]
        except KeyError:
            raise EnvironmentError("This client wants to use a signing method I don't know about: '%s'" % token.algorithm)
        signer = Signer(token.token_string, token.token_secret)
        request_signature = signer.generate_signature(request, timestamp, nonce)
        return request_signature == signature
