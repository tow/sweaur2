from __future__ import absolute_import

import random, re, urllib


lws_re = re.compile('[ \t\v]+')
def normalize_http_header_value(v):
    return lws_re.sub(' ', v).strip()

port_map = {
    u'http': u'80',
    u'https': u'443',
}
def normalize_port_number(scheme, port):
    if scheme not in port_map.keys():
        raise ValueError("'%s' scheme not supported" % scheme)
    if port:
        return unicode(port)
    return port_map[scheme]

def normalize_query_parameters(query):
    return '\n'.join(sorted(
        '%s=%s' % (urllib.quote(p[0], safe='~'), urllib.quote(p[1], safe='~'))
        for p in parse_qsl(query)))

def parse_qsl(querystring):
    # cgi.parse_qsl doesn't deal with parameters without a value
    params = querystring.replace(';', '&').split('&')
    if not params:
        return []
    new_params = []
    for param in params:
        if not param:
            continue
        p = param.split('=', 1)
        if len(p) == 1:
            p = (p[0], '')
        new_params.append((urllib.unquote_plus(p[0]),
                           urllib.unquote_plus(p[1])))
    return new_params

default_allowed_chars = ''.join(chr(i) for i in range(32, 127))
def random_string(length, allowed_chars=default_allowed_chars):
    return ''.join([random.choice(allowed_chars) for i in range(length)])
