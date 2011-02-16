from __future__ import absolute_import

import base64, hashlib, hmac, re, time, urlparse

from .request import Request, RequestSigner
from .utils import normalize_port_number, normalize_query_parameters, random_string


ascii_subset_re = r'[^"^\\]+'
ascii_subset_re_obj = re.compile('^%s$' % ascii_subset_re)
timestamp_re = '[0-9]+'
timestamp_re_obj = re.compile('^%s$' % timestamp_re)


def default_timestamp_generator():
    return unicode(int(time.time()))

# all printable ascii chars except " and \
ascii_subset_list = ''.join(chr(i) for i in range(32, 127) if i not in (34, 92)) 
def default_nonce_generator():
    return random_string(8, ascii_subset_list)


class MACRequestSigner(RequestSigner):
    access_token_re_obj = ascii_subset_re_obj
    access_token_secret_re_obj = ascii_subset_re_obj
    nonce_re_obj = ascii_subset_re_obj

    def __init__(self, access_token_obj,
                 timestamp_generator=default_timestamp_generator,
                 nonce_generator=default_nonce_generator):
        super(MACRequestSigner, self).__init__(access_token_obj)

        assert default_signers[access_token_obj.algorithm] == self.__class__
        self.access_token_secret = access_token_obj.secret
        if not self.access_token_re_obj.match(self.access_token_string):
            raise ValueError("Invalid access_token for MAC authentication")
        if not self.access_token_secret_re_obj.match(self.access_token_secret):
            raise ValueError("Invalid access_token_secret for MAC authentication")
        self.timestamp_generator = timestamp_generator
        self.nonce_generator = nonce_generator

    def sign_request(self, request):
        timestamp = self.timestamp_generator()
        nonce = self.nonce_generator()
        if not timestamp_re_obj.match(timestamp):
            raise ValueError("Invalid timestamp for MAC authentication")
        if not self.nonce_re_obj.match(nonce):
            raise ValueError("Invalid nonce for MAC authentication")
        if 'AUTHORIZATION' in request.headers:
            raise ValueError("This request already has an Authorization header")
        headers = request.headers.copy()
        signature = self.generate_signature(request, timestamp, nonce)
        headers['AUTHORIZATION'] = self.make_authorization_header(timestamp, nonce, signature)
        return Request(request.method, request.uri, headers, request.body)

    def make_authorization_header(self, timestamp, nonce, signature):
        return 'MAC token="%s" timestamp="%s" nonce="%s" signature="%s"' % (
            self.access_token_string, timestamp, nonce, signature)

    def normalized_request_string(self, request, timestamp, nonce):
        bodyhash = ''
        url_obj = urlparse.urlparse(request.uri)
        if not request.host:
            raise ValueError("Request has no Host header")
        port = normalize_port_number(url_obj.scheme, url_obj.port)
        query = normalize_query_parameters(url_obj.query)
        elements = [
           self.access_token_string,
           timestamp,
           nonce,
           bodyhash,
           request.method,
           request.host,
           port,
           url_obj.path,
           query,
        ]
        return ''.join('%s\n' % e for e in elements)


class Hmac_Sha_1_RequestSigner(MACRequestSigner):
    def generate_signature(self, request, timestamp, nonce):
        return base64.b64encode(
            hmac.new(self.access_token_secret,
                     self.normalized_request_string(request, timestamp, nonce),
                     hashlib.sha1).digest()
        )


class Hmac_Sha_256_RequestSigner(MACRequestSigner):
    def generate_signature(self, request, timestamp, nonce):
        return base64.b64encode(
            hmac.new(self.access_token_secret,
                     self.normalized_request_string(request, timestamp, nonce),
                     hashlib.sha256).digest()
        )


# would be nice to make this immutable:
default_signers = {
    'hmac-sha-1':Hmac_Sha_1_RequestSigner,
    'hmac-sha-256':Hmac_Sha_256_RequestSigner,
}
