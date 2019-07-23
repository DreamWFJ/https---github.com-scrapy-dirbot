# -*- coding: utf-8 -*-

import re
import collections

_CRLF_RE = re.compile(r"\r?\n")


class HTTPInputError(Exception):
    """Exception class for malformed HTTP requests or responses
    from remote sources.

    .. versionadded:: 4.0
    """

    pass


class HTTPOutputError(Exception):
    """Exception class for errors in HTTP output.

    .. versionadded:: 4.0
    """

    pass


def to_unicode(value):
    """Converts a string argument to a unicode string.

    If the argument is already a unicode string or None, it is returned
    unchanged.  Otherwise it must be a byte string and is decoded as utf8.
    """
    if isinstance(value, (str, type(None))):
        return value
    if not isinstance(value, bytes):
        raise TypeError("Expected bytes, unicode, or None; got %r" % type(value))
    return value.decode("utf-8")


class _NormalizedHeaderCache(dict):
    """Dynamic cached mapping of header names to Http-Header-Case.

    Implemented as a dict subclass so that cache hits are as fast as a
    normal dict lookup, without the overhead of a python function
    call.

    >>> normalized_headers = _NormalizedHeaderCache(10)
    >>> normalized_headers["coNtent-TYPE"]
    'Content-Type'
    """

    def __init__(self, size):
        super(_NormalizedHeaderCache, self).__init__()
        self.size = size
        self.queue = collections.deque()

    def __missing__(self, key):
        normalized = "-".join([w.capitalize() for w in key.split("-")])
        self[key] = normalized
        self.queue.append(key)
        if len(self.queue) > self.size:
            # Limit the size of the cache.  LRU would be better, but this
            # simpler approach should be fine.  In Python 2.7+ we could
            # use OrderedDict (or in 3.2+, @functools.lru_cache).
            old_key = self.queue.popleft()
            del self[old_key]
        return normalized


_normalized_headers = _NormalizedHeaderCache(1000)


class HTTPHeaders(collections.abc.MutableMapping):
    """A dictionary that maintains ``Http-Header-Case`` for all keys.

    Supports multiple values per key via a pair of new methods,
    `add()` and `get_list()`.  The regular dictionary interface
    returns a single value per key, with multiple values joined by a
    comma.

    >>> h = HTTPHeaders({"content-type": "text/html"})
    >>> list(h.keys())
    ['Content-Type']
    >>> h["Content-Type"]
    'text/html'

    >>> h.add("Set-Cookie", "A=B")
    >>> h.add("Set-Cookie", "C=D")
    >>> h["set-cookie"]
    'A=B,C=D'
    >>> h.get_list("set-cookie")
    ['A=B', 'C=D']

    >>> for (k,v) in sorted(h.get_all()):
    ...    print('%s: %s' % (k,v))
    ...
    Content-Type: text/html
    Set-Cookie: A=B
    Set-Cookie: C=D
    """

    def __init__(self, *args, **kwargs):
        self._dict = {}
        self._as_list = {}
        self._last_key = None
        if len(args) == 1 and len(kwargs) == 0 and isinstance(args[0], HTTPHeaders):
            # Copy constructor
            for k, v in args[0].get_all():
                self.add(k, v)
        else:
            # Dict-style initialization
            self.update(*args, **kwargs)

    # new public methods

    def add(self, name, value):
        """Adds a new value for the given key."""
        norm_name = _normalized_headers[name]
        self._last_key = norm_name
        if norm_name in self:
            self._dict[norm_name] = (
                    to_unicode(self[norm_name]) + "," + to_unicode(value)
            )
            self._as_list[norm_name].append(value)
        else:
            self[norm_name] = value

    def get_list(self, name: str):
        """Returns all values for the given header as a list."""
        norm_name = _normalized_headers[name]
        return self._as_list.get(norm_name, [])

    def get_all(self):
        """Returns an iterable of all (name, value) pairs.

        If a header has multiple values, multiple pairs will be
        returned with the same name.
        """
        for name, values in self._as_list.items():
            for value in values:
                yield (name, value)

    def parse_line(self, line):
        """Updates the dictionary with a single header line.

        >>> h = HTTPHeaders()
        >>> h.parse_line("Content-Type: text/html")
        >>> h.get('content-type')
        'text/html'
        """
        if line[0].isspace():
            # continuation of a multi-line header
            if self._last_key is None:
                raise HTTPInputError("first header line cannot start with whitespace")
            new_part = " " + line.lstrip()
            self._as_list[self._last_key][-1] += new_part
            self._dict[self._last_key] += new_part
        else:
            try:
                name, value = line.split(":", 1)
            except ValueError:
                raise HTTPInputError("no colon in header line")
            self.add(name, value.strip())

    @classmethod
    def parse(cls, headers: str):
        """Returns a dictionary from HTTP header text.

        >>> h = HTTPHeaders.parse("Content-Type: text/html\\r\\nContent-Length: 42\\r\\n")
        >>> sorted(h.items())
        [('Content-Length', '42'), ('Content-Type', 'text/html')]

        .. versionchanged:: 5.1

           Raises `HTTPInputError` on malformed headers instead of a
           mix of `KeyError`, and `ValueError`.

        """
        h = cls()
        for line in _CRLF_RE.split(headers):
            if line:
                h.parse_line(line)
        return h

    # MutableMapping abstract method implementations.

    def __setitem__(self, name, value):
        norm_name = _normalized_headers[name]
        self._dict[norm_name] = value
        self._as_list[norm_name] = [value]

    def __getitem__(self, name):
        return self._dict[_normalized_headers[name]]

    def __delitem__(self, name):
        norm_name = _normalized_headers[name]
        del self._dict[norm_name]
        del self._as_list[norm_name]

    def __len__(self):
        return len(self._dict)

    def __iter__(self):
        return iter(self._dict)

    def copy(self):
        # defined in dict but not in MutableMapping.
        return HTTPHeaders(self)

    # Use our overridden copy method for the copy.copy module.
    # This makes shallow copies one level deeper, but preserves
    # the appearance that HTTPHeaders is a single container.
    __copy__ = copy

    def __str__(self):
        lines = []
        for name, value in self.get_all():
            lines.append("%s: %s\n" % (name, value))
        return "".join(lines)

    __unicode__ = __str__


RequestStartLine = collections.namedtuple(
    "RequestStartLine", ["method", "path", "version"]
)


def parse_request_start_line(line):
    """Returns a (method, path, version) tuple for an HTTP 1.x request line.

    The response is a `collections.namedtuple`.

    >>> parse_request_start_line("GET /foo HTTP/1.1")
    RequestStartLine(method='GET', path='/foo', version='HTTP/1.1')
    """
    try:
        method, path, version = line.split(" ")
    except ValueError:
        raise HTTPInputError("Malformed HTTP request line")
    if not re.match(r"^HTTP/1\.[0-9]$", version):
        raise HTTPInputError(
            "Malformed HTTP version in HTTP Request-Line: %r" % version
        )
    return RequestStartLine(method, path, version)


ResponseStartLine = collections.namedtuple(
    "ResponseStartLine", ["version", "code", "reason"]
)


def parse_response_start_line(line):
    """Returns a (version, code, reason) tuple for an HTTP 1.x response line.

    The response is a `collections.namedtuple`.

    >>> parse_response_start_line("HTTP/1.1 200 OK")
    ResponseStartLine(version='HTTP/1.1', code=200, reason='OK')
    """
    line = to_unicode(line)
    match = re.match("(HTTP/1.[0-9]) ([0-9]+) ([^\r]*)", line)
    if not match:
        raise HTTPInputError("Error parsing response start line")
    return ResponseStartLine(match.group(1), int(match.group(2)), match.group(3))
