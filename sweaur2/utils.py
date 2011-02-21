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

authtype_re_obj = re.compile(r'^(?P<authtype>[A-Za-z0-9_-]+)(?P<parameters>[ \t\v]+.*)')
parameter_re_obj = re.compile(r'^[ \t\v]*(?P<title>[A-Za-z0-9_-]+)="(?P<value>[^"^\\]*)"(?P<rest>.*)[ \t\v]*$')
def parse_auth_header(header, paramdict):
    m = authtype_re_obj.match(header)
    if not m:
        raise ValueError
    authtype, rest_of_header = m.groups()
    if not paramdict:
        return authtype, rest_of_header.strip()
    parameter_dict = {}
    while rest_of_header:
        m = parameter_re_obj.match(rest_of_header)
        if not m:
            raise ValueError
        title, value, rest_of_header = m.groups()
        if title in parameter_dict:
            raise ValueError
        parameter_dict[title] = value
    return authtype, parameter_dict

def quoted_string(s):
    """Escape all double quotes and backslashes"""
    return s.replace('\\', '\\\\').replace('"', '\\"')

def parse_scope_string(scope_string):
    scope_string = normalize_http_header_value(scope_string)
    if scope_string:
        return set(scope_string.split(' '))
    else:
        return set()

def is_first_scope_string_in_second(scope_string_1, scope_string_2):
    """Are all the scopes in scope_string_1 within the scopes in scope_string_2?"""
    return not bool(parse_scope_string(scope_string_1) - parse_scope_string(scope_string_2))
