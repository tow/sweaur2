from __future__ import absolute_import

from .utils import normalize_http_header_value, normalize_port_number, normalize_query_parameters, parse_qsl

all_cases = (
    (normalize_http_header_value,
        (
            (('example.com',), 'example.com'),
            ((' example.com',), 'example.com'),
            (('example.com   ',), 'example.com'),
            ((' \texample.com  \t ',), 'example.com'),
            (('text/html',), 'text/html'),
            (('text/html; charset=utf-8',), 'text/html; charset=utf-8'),
            ((' text/html; \t \v charset=utf-8',), 'text/html; charset=utf-8'),
        ),
        (
        ),
    ),
    (normalize_port_number,
        (
            (('http', 80), '80'),
            (('http', 8000), '8000'),
            (('http', 443), '443'),
            (('http', None), '80'),
            (('https', 80), '80'),
            (('https', 8000), '8000'),
            (('https', 443), '443'),
            (('https', None), '443'),
        ),
        (
            (('gopher', 70), ValueError),
        ),
    ),
    (parse_qsl,
        (
            (('a=1',), [('a', '1')]),
            (('a=1&b=2',), [('a', '1'), ('b', '2')]),
            (('a=1&b=2&c=3',), [('a', '1'), ('b', '2'), ('c', '3')]),
            (('a=1&b=2;c=3',), [('a', '1'), ('b', '2'), ('c', '3')]),
            (('a=1&a=2;c=3',), [('a', '1'), ('a', '2'), ('c', '3')]),
            (('a=1%3D&a=2;c=3',), [('a', '1='), ('a', '2'), ('c', '3')]),
            (('a=1%3D&a=2;c%3D=3',), [('a', '1='), ('a', '2'), ('c=', '3')]),
            (('b5=%3D%253D&a3=a&c%40=&a2=r%20b&c2&a3=2+q',), [('b5', '=%3D'), ('a3', 'a'), ('c@', ''), ('a2', 'r b'), ('c2', ''), ('a3', '2 q')]),
        ),
        (
        ),
    ),
    (normalize_query_parameters,
        (
            (('a=1',), 'a=1'),
            (('a=1&b=1',), 'a=1\nb=1'),
            (('a=1;b=1',), 'a=1\nb=1'),
            (('b=1&a=1',), 'a=1\nb=1'),
            (('a=2;a=1',), 'a=1\na=2'),
            (('b5=%3D%253D&a3=a&c%40=&a2=r%20b&c2&a3=2+q',), 'a2=r%20b\na3=2%20q\na3=a\nb5=%3D%253D\nc%40=\nc2='),
            (('a=~',), 'a=~'), # by default, python will try to escape tilde
            (('a=/',), 'a=%2F'), # by default, python will not try to escape a forward slash
        ),
        (
        ),
    ),
)

def check_ok(fn, i, o):
    try:
        assert fn(*i) == o
    except AssertionError:
       print fn(*i)
       print o

def check_fails(fn, i, e):
    try:
        fn(*i)
    except e:
        pass
    else:
        assert False

def test_everything():
    for fn, ok_cases, failure_cases in all_cases:
        for i, o in ok_cases:
            yield check_ok, fn, i, o
        for i, e in failure_cases:
            yield check_fails, fn, i, e
