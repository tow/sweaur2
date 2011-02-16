from __future__ import absolute_import

import urllib, urlparse

from .request import Request, RequestSigner
from .utils import parse_qsl


class BearerHeaderRequestSigner(RequestSigner):
    def sign_request(self, request):
        if 'AUTHORIZATION' in request.headers:
            raise ValueError("Request already has Authorization header")
        headers = request.headers.copy()
        headers['Authorization'] = 'Bearer %s' % self.access_token_string
        return Request(request.method, request.uri, headers, request.body)


class BearerBodyRequestSigner(RequestSigner):
    def sign_request(self, request):
        if request.method in ('GET', 'HEAD'):
            raise ValueError("Cannot sign the body of a '%s' request" % request.method)
        if request.headers.get('CONTENT-TYPE') != 'application/x-www-form-urlencoded':
            raise ValueError("Cannot sign the body of a request which is not application/x-www-form-urlencoded")
        try:
            qs = parse_qsl(request.body)
        except ValueError:
            raise ValueError("Request body is not a valid querystring")
        if 'oauth_token' in dict(qs):
            raise ValueError("Request body already includes oauth_token parameter")
        qs.append(('oauth_token', self.access_token_string))
        return Request(request.method, request.uri, request.headers.copy(), urllib.urlencode(qs))
 

class BearerUriRequestSigner(RequestSigner):
    def sign_request(self, request):
        urlobj = urlparse.urlparse(request.uri)
        try:
            qs = parse_qsl(urlobj.query)
        except ValueError:
            raise ValueError("Request URI has invalid query string")
        if 'oauth_token' in dict(qs):
            raise ValueError("Request URI already includes oauth_token parameter")
        qs.append(('oauth_token', self.access_token_string))
        uri = urlparse.urlunparse((
            urlobj.scheme,
            urlobj.netloc,
            urlobj.path,
            urlobj.params,
            urllib.urlencode(qs),
            urlobj.fragment,
        ))
        return Request(request.method, uri, request.headers.copy(), request.body)


# would be nice to make this immutable:
default_signers = {
    'header':BearerHeaderRequestSigner,
    'body':BearerBodyRequestSigner,
    'uri':BearerUriRequestSigner,
}
