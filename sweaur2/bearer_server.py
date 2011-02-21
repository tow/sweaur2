from __future__ import absolute_import

import urlparse

from .exceptions import InvalidClient
from .request import Request, RequestChecker
from .utils import parse_auth_header, parse_qsl


class BearerRequestChecker(RequestChecker):
    token_type = 'bearer'
    auth_type = 'Bearer'

    def do_request_check(self, request):
        access_token_string, token_from = self.check_all_request_methods(request)
        try:
            token_obj = self.token_store.get_access_token(access_token_string, self.token_type)
        except self.token_store.NoSuchToken:
            raise InvalidClient()
        if token_from != 'header' and not token_obj.extra_parameters[token_from]:
            raise self.AuthenticationNotPermitted()
        return token_obj

    def check_all_request_methods(self, request):
        try:
            token_from_headers = self.check_authorization_header(request)
        except self.AuthenticationNotFound:
            token_from_headers = None
        try:
            token_from_body = self.check_authorization_body(request)
        except self.AuthenticationNotFound:
            token_from_body = None
        try:
            token_from_request = self.check_authorization_request(request)
        except self.AuthenticationNotFound:
            token_from_request = None
        tokens = (token_from_headers, token_from_body, token_from_request)
        true_tokens = [int(bool(token)) for token in tokens]
        if sum(true_tokens) == 0:
            # User didn't try to authenticate at all.
            raise self.AuthenticationNotFound()
        if sum(true_tokens) > 1:
            # User tried to authenticate in too many ways.
            raise self.AuthenticationNotPermitted()
        token_index = true_tokens.index(1)
        token_from = ('header', 'body', 'uri')[token_index]
        token = tokens[token_index]
        return token, token_from

    def check_authorization_header(self, request):
        try:
            auth_header = request.headers['AUTHORIZATION']
        except KeyError:
            raise self.AuthenticationNotFound()
        auth_type, parameters = parse_auth_header(auth_header, False)
        if auth_type.lower() != self.token_type:
            raise self.AuthenticationNotFound()   
        return parameters

    def check_authorization_request(self, request):
        querystring = urlparse.urlparse(request.uri).query
        return self.check_query_params(querystring)

    def check_authorization_body(self, request):
        if request.method in ('GET', 'HEAD'):
            raise self.AuthenticationNotFound()
        if request.headers.get('CONTENT-TYPE') != 'application/x-www-form-urlencoded':
            raise self.AuthenticationNotFound()
        # Don't understand what it's saying about single-part.
        return self.check_query_params(request.body)

    def check_query_params(self, querystring):
        try:
            qs = parse_qsl(querystring)
        except ValueError:
            raise self.AuthenticationNotFound()
        try:
            oauth_tokens = [v for k, v in qs if k == 'oauth_token']
        except KeyError:
            raise self.AuthenticationNotFound()
        if len(oauth_tokens) != 1:
            raise self.AuthenticationNotFound()
        return oauth_tokens[0]
