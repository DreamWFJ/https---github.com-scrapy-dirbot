# -*- coding: utf-8 -*-

import os
import re
import sys
import time
import hmac
import zlib
import array
import email
import struct
import json
import hashlib
import collections
from base64 import encodebytes
from collections import namedtuple
from urllib.parse import urlparse
from twisted.python import log
from twisted.internet import protocol, reactor, endpoints

FrameHeader = namedtuple('FrameHeader', "fin operate_code rsv1 rsv2 rsv3 payload_length mask")
_CRLF_RE = re.compile(r"\r?\n")


class WebSocketError(Exception):
    pass


class WebSocketClosedError(WebSocketError):
    pass


class _DecompressTooLargeError(Exception):
    pass


class HTTPInputError(Exception):
    pass


class HTTPOutputError(Exception):
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


def utf8(value):
    """Converts a string argument to a byte string.

    If the argument is already a byte string or None, it is returned unchanged.
    Otherwise it must be a unicode string and is encoded as utf8.
    """
    if isinstance(value, (bytes, type(None))):
        return value
    if not isinstance(value, str):
        raise TypeError("Expected bytes, unicode, or None; got %r" % type(value))
    return value.encode("utf-8")


class _WebSocketParams(object):
    def __init__(self, ping_interval, ping_timeout,
                 max_message_size=None, compression_options=None, request=None):
        self.ping_interval = ping_interval
        self.ping_timeout = ping_timeout
        self.max_message_size = max_message_size
        self.compression_options = compression_options
        self.request = request


class _PerMessageDeflateCompressor(object):
    GZIP_LEVEL = 6

    def __init__(self, persistent, max_wbits, compression_options):
        if max_wbits is None:
            max_wbits = zlib.MAX_WBITS
        # There is no symbolic constant for the minimum wbits value.
        if not (8 <= max_wbits <= zlib.MAX_WBITS):
            raise ValueError(
                "Invalid max_wbits value %r; allowed range 8-%d",
                max_wbits,
                zlib.MAX_WBITS,
            )
        self._max_wbits = max_wbits

        if (
                compression_options is None
                or "compression_level" not in compression_options
        ):
            self._compression_level = _PerMessageDeflateCompressor.GZIP_LEVEL
        else:
            self._compression_level = compression_options["compression_level"]

        if compression_options is None or "mem_level" not in compression_options:
            self._mem_level = 8
        else:
            self._mem_level = compression_options["mem_level"]

        if persistent:
            self._compressor = self._create_compressor()
        else:
            self._compressor = None

    def _create_compressor(self):
        return zlib.compressobj(
            self._compression_level, zlib.DEFLATED, -self._max_wbits, self._mem_level
        )

    def compress(self, data):
        compressor = self._compressor or self._create_compressor()
        data = compressor.compress(data) + compressor.flush(zlib.Z_SYNC_FLUSH)
        assert data.endswith(b"\x00\x00\xff\xff")
        return data[:-4]


class _PerMessageDeflateDecompressor(object):
    def __init__(self, persistent, max_wbits, max_message_size, compression_options):
        self._max_message_size = max_message_size
        if max_wbits is None:
            max_wbits = zlib.MAX_WBITS
        if not (8 <= max_wbits <= zlib.MAX_WBITS):
            raise ValueError(
                "Invalid max_wbits value %r; allowed range 8-%d",
                max_wbits,
                zlib.MAX_WBITS,
            )
        self._max_wbits = max_wbits
        if persistent:
            self._decompressor = (
                self._create_decompressor()
            )
        else:
            self._decompressor = None

    def _create_decompressor(self):
        return zlib.decompressobj(-self._max_wbits)

    def decompress(self, data):
        decompressor = self._decompressor or self._create_decompressor()
        result = decompressor.decompress(
            data + b"\x00\x00\xff\xff", self._max_message_size
        )
        if decompressor.unconsumed_tail:
            raise _DecompressTooLargeError()
        return result


def _parseparam(s):
    while s[:1] == ";":
        s = s[1:]
        end = s.find(";")
        while end > 0 and (s.count('"', 0, end) - s.count('\\"', 0, end)) % 2:
            end = s.find(";", end + 1)
        if end < 0:
            end = len(s)
        f = s[:end]
        yield f.strip()
        s = s[end:]


def _parse_header(line):
    r"""Parse a Content-type like header.

    Return the main content-type and a dictionary of options.

    >>> d = "form-data; foo=\"b\\\\a\\\"r\"; file*=utf-8''T%C3%A4st"
    >>> ct, d = _parse_header(d)
    >>> ct
    'form-data'
    >>> d['file'] == r'T\u00e4st'.encode('ascii').decode('unicode_escape')
    True
    >>> d['foo']
    'b\\a"r'
    """
    parts = _parseparam(";" + line)
    key = next(parts)
    # decode_params treats first argument special, but we already stripped key
    params = [("Dummy", "value")]
    for p in parts:
        i = p.find("=")
        if i >= 0:
            name = p[:i].strip().lower()
            value = p[i + 1:].strip()
            params.append((name, to_unicode(value)))
    decoded_params = email.utils.decode_params(params)
    decoded_params.pop(0)  # get rid of the dummy again
    pdict = {}
    for name, decoded_value in decoded_params:
        value = email.utils.collapse_rfc2231_value(decoded_value)
        if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
            value = value[1:-1]
        pdict[name] = value
    return key, pdict


def _encode_header(key, pdict):
    """Inverse of _parse_header.

    >>> _encode_header('permessage-deflate',
    ...     {'client_max_window_bits': 15, 'client_no_context_takeover': None})
    'permessage-deflate; client_max_window_bits=15; client_no_context_takeover'
    """
    if not pdict:
        return key
    out = [key]
    # Sort the parameters just to make it easy to test.
    for k, v in sorted(pdict.items()):
        if v is None:
            out.append(k)
        else:
            # TODO: quote if necessary.
            out.append("%s=%s" % (k, v))
    return "; ".join(out)


class StateMixin:
    """
    状态设置
    """
    STATE_CLOSED = 0
    STATE_OPEN = 1
    STATE_CONNECTING = 2
    STATE_PROXY_CONNECTING = 3
    STATE_CLOSING = 4

    def _set_state(self, v):
        self._state = v

    def _set_closed(self):
        self._set_state(self.STATE_CLOSED)

    def _set_open(self):
        self._set_state(self.STATE_OPEN)

    def _set_connecting(self):
        self._set_state(self.STATE_CONNECTING)

    def _set_proxy_connecting(self):
        self._set_state(self.STATE_PROXY_CONNECTING)

    def _set_closing(self):
        self._set_state(self.STATE_CLOSING)

    def _check_state(self, v):
        return self._state == v

    @property
    def _is_closed(self):
        return self._check_state(self.STATE_CLOSED)

    @property
    def _is_open(self):
        return self._check_state(self.STATE_OPEN)

    @property
    def _is_connecting(self):
        return self._check_state(self.STATE_CONNECTING)

    @property
    def _is_proxy_connecting(self):
        return self._check_state(self.STATE_PROXY_CONNECTING)

    @property
    def _is_closing(self):
        return self._check_state(self.STATE_CLOSING)

    def _view_state(self):
        return self._state


class WebSocketProtocol(StateMixin, protocol.Protocol):
    FIN = 0x80
    RSV1 = 0x40
    RSV2 = 0x20
    RSV3 = 0x10
    RSV_MASK = RSV1 | RSV2 | RSV3
    OPCODE_MASK = 0x0F

    _default_max_message_size = 10 * 1024 * 1024

    def __init__(self, factory, ping_interval=None, ping_timeout=None,
                 max_message_size=None, compression_options=None):
        self.factory = factory
        self._buffer = b''
        self._state = None
        self._compressor = None
        self._selected_subprotocol = None
        self.close_code = None
        self.close_reason = None
        self._frame_length = None
        self._frame_mask = None
        self._frame_compressed = None
        self._fragmented_message_opcode = None
        self._fragmented_message_buffer = None
        self.server_terminated = None
        self.client_terminated = None
        self._waiting = None
        self.mask_outgoing = True
        self.headers = None
        self.http_status_line = None
        self._decompressor = None
        self.last_ping = 0
        self.last_pong = 0
        self.ping_callback = None
        self.options = _WebSocketParams(
            ping_interval=ping_interval,
            ping_timeout=ping_timeout,
            max_message_size=max_message_size or self._default_max_message_size,
            compression_options=compression_options,
            request=self.factory.request,
        )

    def set_status(self, status=None, reason=None):
        self.close_code = status
        self.close_reason = reason

    @property
    def ping_interval(self):
        interval = self.options.ping_interval
        if interval is not None:
            return interval
        return 0

    @property
    def ping_timeout(self):
        timeout = self.options.ping_timeout
        if timeout is not None:
            return timeout
        assert self.ping_interval is not None
        return max(3 * self.ping_interval, 30)

    @property
    def selected_subprotocol(self):
        return self._selected_subprotocol

    @selected_subprotocol.setter
    def selected_subprotocol(self, value):
        self._selected_subprotocol = value

    @staticmethod
    def call_later(delay, callback, *args, **kwargs):
        return reactor.callLater(delay, callback, *args, **kwargs)

    @property
    def current_time(self):
        return time.time()

    @staticmethod
    def cancel_callback(o):
        if o.active():
            o.cancel()

    @staticmethod
    def compute_accept_value(key):
        """Computes the value for the Sec-WebSocket-Accept header,
        given the value for Sec-WebSocket-Key.
        """
        sha1 = hashlib.sha1()
        sha1.update(utf8(key) + b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11")
        return encodebytes(sha1.digest()).strip()

    @staticmethod
    def _websocket_mask(mask: bytes, data: bytes) -> bytes:
        """Websocket masking function.

        `mask` is a `bytes` object of length 4; `data` is a `bytes` object of any length.
        Returns a `bytes` object of the same length as `data` with the mask applied
        as specified in section 5.3 of RFC 6455.

        This pure-python implementation may be replaced by an optimized version when available.
        """
        mask_arr = array.array("B", mask)
        unmasked_arr = array.array("B", data)
        for i in range(len(data)):
            unmasked_arr[i] = unmasked_arr[i] ^ mask_arr[i % 4]
        return unmasked_arr.tobytes()

    def dataReceived(self, data):
        """
        receive data
        :param data:
        :return:
        """
        self._buffer += data
        if self._is_open or self._is_closing:
            while self.process_frame() and not self._is_closed:
                pass
        elif self._is_proxy_connecting:
            self.process_proxy_connect()
        elif self._is_connecting:
            self.process_handshake()
        elif self._is_closed:
            pass
        else:
            raise Exception(f"invalid state: {self._state}")

    def _abort(self):
        self.client_terminated = True
        self.server_terminated = True
        self._set_closed()
        self.transport.abortConnection()

    def close(self, code=None, reason=None):
        self._set_closing()
        if not self.server_terminated:
            if code is None and reason is not None:
                code = 1000  # "normal closure" status code
            if code is None:
                close_data = b""
            else:
                close_data = struct.pack(">H", code)
            if reason is not None:
                close_data += utf8(reason)
            self._write_frame(True, 0x8, close_data)
            self.server_terminated = True
        if self.client_terminated:
            if self._waiting is not None:
                self.cancel_callback(self._waiting)
                self._waiting = None
            self.transport.loseConnection()
        elif self._waiting is None:
            # Give the client a few seconds to complete a clean shutdown,
            # otherwise just close the connection.
            self._waiting = self.call_later(5, self._abort)
        self._run_callback(self.on_closed, code, reason)

    def process_frame(self):
        buffered_len = len(self._buffer)
        n = 2

        if buffered_len < n:
            return False
        header, mask_payloadlen = struct.unpack("BB", self._buffer[:n])
        is_final_frame = header & self.FIN
        reserved_bits = header & self.RSV_MASK
        opcode = header & self.OPCODE_MASK
        opcode_is_control = opcode & 0x8
        if self._decompressor is not None and opcode != 0:
            self._frame_compressed = bool(reserved_bits & self.RSV1)
            reserved_bits &= ~self.RSV1
        if reserved_bits:
            # client is using as-yet-undefined extensions; abort
            self._abort()
            return False
        is_masked = bool(mask_payloadlen & 0x80)
        payloadlen = mask_payloadlen & 0x7F
        # Parse and validate the length.
        if opcode_is_control and payloadlen >= 126:
            # control frames must have payload < 126
            self._abort()
            return False
        if payloadlen < 126:
            self._frame_length = payloadlen
        elif payloadlen == 126:
            n += 2
            if buffered_len < n:
                return False
            payloadlen = struct.unpack("!H", self._buffer[n - 2:n])[0]
        elif payloadlen == 127:
            n += 8
            if buffered_len < n:
                return False
            payloadlen = struct.unpack("!Q", self._buffer[n - 8:n])[0]
        new_len = payloadlen
        if self._fragmented_message_buffer is not None:
            new_len += len(self._fragmented_message_buffer)
        if new_len > self._default_max_message_size:
            self.close(1009, "message too big")
            self._abort()
            return False
        if is_masked:
            n += 4
            if buffered_len < n:
                return False
            self._frame_mask = self._buffer[n - 4:n]

        n += payloadlen
        if buffered_len < n:
            return False

        data = self._buffer[n - payloadlen:n]
        if is_masked:
            assert self._frame_mask is not None
            data = self._websocket_mask(self._frame_mask, data)

        # Decide what to do with this frame.
        if opcode_is_control:
            # control frames may be interleaved with a series of fragmented
            # data frames, so control frames must not interact with
            # self._fragmented_*
            if not is_final_frame:
                # control frames must not be fragmented
                self._abort()
                return False
        elif opcode == 0:  # continuation frame
            if self._fragmented_message_buffer is None:
                # nothing to continue
                self._abort()
                return False
            self._fragmented_message_buffer += data
            if is_final_frame:
                opcode = self._fragmented_message_opcode
                data = self._fragmented_message_buffer
                self._fragmented_message_buffer = None
        else:  # start of new data message
            if self._fragmented_message_buffer is not None:
                # can't start new message until the old one is finished
                self._abort()
                return False
            if not is_final_frame:
                self._fragmented_message_opcode = opcode
                self._fragmented_message_buffer = data

        self._buffer = self._buffer[n:]
        if is_final_frame:
            self._handle_message(opcode, data)

    def _handle_message(self, opcode, data):
        if self.client_terminated:
            return None

        if self._frame_compressed:
            assert self._decompressor is not None
            try:
                data = self._decompressor.decompress(data)
            except _DecompressTooLargeError:
                self.close(1009, "message too big after decompression")
                self._abort()
                return None

        if opcode == 0x1:
            # UTF-8 data
            try:
                decoded = data.decode("utf-8")
            except UnicodeDecodeError:
                self._abort()
                return None
            return self._run_callback(self.on_message, decoded)
        elif opcode == 0x2:
            # Binary data
            return self._run_callback(self.on_message, data)
        elif opcode == 0x8:
            # Close
            self.client_terminated = True
            if len(data) >= 2:
                self.close_code = struct.unpack(">H", data[:2])[0]
            if len(data) > 2:
                self.close_reason = to_unicode(data[2:])
            # Echo the received close code, if any (RFC 6455 section 5.5.1).
            self.close(self.close_code, self.close_reason)
        elif opcode == 0x9:
            # Ping
            self._write_frame(True, 0xA, data)
            self._run_callback(self.on_ping, data)
        elif opcode == 0xA:
            # Pong
            self.last_pong = self.current_time
            return self._run_callback(self.on_pong, data)
        else:
            self._abort()

    def on_pong(self, data: bytes) -> None:
        """Invoked when the response to a ping frame is received."""
        pass

    def on_ping(self, data: bytes) -> None:
        """Invoked when the a ping frame is received."""
        pass

    def _run_callback(self, callback, *args, **kwargs):
        """Runs the given callback with exception handling.

        If the callback is a coroutine, returns its Future. On error, aborts the
        websocket connection and returns None.
        """
        try:
            # print("callback: ", callback, *args, **kwargs)
            result = callback(*args, **kwargs)
        except Exception:
            import traceback
            traceback.print_exc()
            log.err(sys.exc_info())
            self._abort()
        else:
            return result

    def process_proxy_connect(self):
        """
        process proxy connect
        :return:
        """
        pass

    def on_open(self, addr):
        """
        connect build success
        :param addr:
        :return:
        """
        raise NotImplementedError

    def on_message(self, data):
        """
        receive message
        :param data:
        :return:
        """
        raise NotImplementedError

    def on_closed(self, code=None, reason=None):
        """
        connection be closed by peer
        :param code:
        :param reason:
        :return:
        """
        raise NotImplementedError

    @staticmethod
    def create_security_websocket_key():
        """
        创建websocket安全key
        :return:
        """
        randomness = os.urandom(16)
        return encodebytes(randomness).decode('utf-8').strip()

    @staticmethod
    def _get_compressor_options(side, agreed_parameters, compression_options):
        """Converts a websocket agreed_parameters set to keyword arguments
        for our compressor objects.
        """
        options = dict(
            persistent=(side + "_no_context_takeover") not in agreed_parameters
        )
        wbits_header = agreed_parameters.get(side + "_max_window_bits", None)
        if wbits_header is None:
            options["max_wbits"] = zlib.MAX_WBITS
        else:
            options["max_wbits"] = int(wbits_header)
        options["compression_options"] = compression_options
        return options

    def _create_compressors(self, side, agreed_parameters, compression_options=None):
        allowed_keys = [
            "server_no_context_takeover",
            "client_no_context_takeover",
            "server_max_window_bits",
            "client_max_window_bits",
        ]
        allowed_keys = set(allowed_keys)

        for key in agreed_parameters:
            if key not in allowed_keys:
                raise ValueError("unsupported compression parameter %r" % key)
        other_side = "client" if (side == "server") else "server"
        self._compressor = _PerMessageDeflateCompressor(
            **self._get_compressor_options(side, agreed_parameters, compression_options)
        )
        self._decompressor = _PerMessageDeflateDecompressor(
            max_message_size=self._default_max_message_size,
            **self._get_compressor_options(
                other_side, agreed_parameters, compression_options
            )
        )

    def _write_frame(self, fin, opcode, data, flags=0):
        data_len = len(data)
        if opcode & 0x8:
            if not fin:
                raise ValueError("control frames may not be fragmented")
            if data_len > 125:
                raise ValueError("control frame payloads may not exceed 125 bytes")
        fin_bit = self.FIN if fin else 0
        frame = struct.pack("B", fin_bit | opcode | flags)
        mask_bit = 0x80 if self.mask_outgoing else 0
        if data_len < 126:
            frame += struct.pack("B", data_len | mask_bit)
        elif data_len <= 0xFFFF:
            frame += struct.pack("!BH", 126 | mask_bit, data_len)
        else:
            frame += struct.pack("!BQ", 127 | mask_bit, data_len)
        if self.mask_outgoing:
            mask = os.urandom(4)
            data = mask + self._websocket_mask(mask, data)
        frame += data
        self.transport.write(frame)

    def write_message(self, message, binary=False):
        opcode = 0x2 if binary else 0x1
        message = utf8(message)
        assert isinstance(message, bytes)
        flags = 0
        if self._compressor:
            message = self._compressor.compress(message)
            flags |= self.RSV1
        try:
            fut = self._write_frame(True, opcode, message, flags=flags)
        except Exception as e:
            print("write_message error: ", e)

    def write_ping(self, data=b""):
        assert isinstance(data, bytes)
        self._write_frame(True, 0x9, data)

    @staticmethod
    def _parse_headers(data):
        data_str = to_unicode(data.decode('latin1')).lstrip("\r\n")
        eol = data_str.find("\n")
        start_line = data_str[:eol].rstrip("\r")
        headers = HTTPHeaders.parse(data_str[eol:])
        return start_line, headers

    def start_pinging(self) -> None:
        """Start sending periodic pings to keep the connection alive"""
        assert self.ping_interval is not None
        if self.ping_interval > 0:
            self.last_ping = self.last_pong = self.current_time
            self.ping_callback = self.call_later(self.ping_interval, self.periodic_ping)

    def periodic_ping(self) -> None:
        """Send a ping to keep the websocket alive

        Called periodically if the websocket_ping_interval is set and non-zero.
        """
        if (self._is_closed or self.client_terminated or self.server_terminated) \
                and self.ping_callback is not None:
            self.cancel_callback(self.ping_callback)
            return

        # Check for timeout on pong. Make sure that we really have
        # sent a recent ping in case the machine with both server and
        # client has been suspended since the last ping.
        now = self.current_time
        since_last_pong = now - self.last_pong
        since_last_ping = now - self.last_ping
        assert self.ping_interval is not None
        assert self.ping_timeout is not None
        if (
                since_last_ping < 2 * self.ping_interval
                and since_last_pong > self.ping_timeout
        ):
            self.close()
            return

        self.write_ping(b"")
        self.last_ping = now


class WebSocketServerProtocol(WebSocketProtocol):
    def __init__(self, factory, peer, compression_options=None, ping_interval=None, ping_timeout=None,
                 max_message_size=None):
        super().__init__(factory, ping_interval, ping_timeout, max_message_size, compression_options)
        self.handshake_timeout_callback = None
        self.handshake_timeout = 5
        self.peer = peer

    def connectionMade(self):
        self.factory.numProtocols += 1
        self._set_connecting()
        self._buffer = b''
        self.handshake_timeout_callback = self.call_later(self.handshake_timeout, self.on_handshake_timeout)

    def on_handshake_timeout(self):
        print("on_handshake_timeout")
        if self._is_connecting:
            self._abort()

    def connectionLost(self, reason=protocol.connectionDone):
        self.factory.numProtocols -= 1
        self._set_closed()

    def _handle_websocket_headers(self):
        """Verifies all invariant- and required headers

        If a header is missing or have an incorrect value ValueError will be
        raised
        """
        fields = ("Host", "Sec-Websocket-Key", "Sec-Websocket-Version")
        if not all(map(lambda f: self.headers.get(f), fields)):
            raise ValueError("Missing/Invalid WebSocket headers")

    @staticmethod
    def _parse_extensions_header(headers):
        extensions = headers.get("Sec-WebSocket-Extensions", "")
        if extensions:
            return [_parse_header(e.strip()) for e in extensions.split(",")]
        return []

    def process_handshake(self):
        self.cancel_callback(self.handshake_timeout_callback)
        end_of_header = self._buffer.find(b"\x0d\x0a\x0d\x0a")
        if end_of_header < 0:
            return
        n = end_of_header + 4
        self.http_status_line, self.headers = self._parse_headers(self._buffer[:n])
        request_start_line = parse_request_start_line(self.http_status_line)
        try:
            assert request_start_line.path == self.factory.request.path
        except AssertionError:
            self.close(400)
            return
        try:
            self._handle_websocket_headers()
        except ValueError:
            self.close(400)
            return
        else:
            subprotocol_header = self.headers.get("Sec-WebSocket-Protocol")
            if subprotocol_header:
                subprotocols = [s.strip() for s in subprotocol_header.split(",")]
            else:
                subprotocols = []
            self.selected_subprotocol = subprotocols

            extensions = self._parse_extensions_header(self.headers)
            for ext in extensions:
                if ext[0] == "permessage-deflate" and self._compression_options is not None:
                    # TODO: negotiate parameters if compression_options
                    # specifies limits.
                    self._create_compressors("server", ext[1], self._compression_options)
                    if (
                            "client_max_window_bits" in ext[1]
                            and ext[1]["client_max_window_bits"] is None
                    ):
                        # Don't echo an offered client_max_window_bits
                        # parameter with no value.
                        del ext[1]["client_max_window_bits"]
                    self.headers.set_header(
                        "Sec-WebSocket-Extensions",
                        _encode_header("permessage-deflate", ext[1]),
                    )
                    break

            self._buffer = self._buffer[n:]
            sec_websocket_accept = self.compute_accept_value(self.headers.get("Sec-Websocket-Key"))
            response = "HTTP/1.1 101 Switching Protocols\x0d\x0a"
            response += "Upgrade: WebSocket\x0d\x0a"
            response += "Connection: Upgrade\x0d\x0a"
            if len(subprotocols):
                response += "Sec-WebSocket-Protocol: %s\x0d\x0a" % ', '.join(subprotocols)
            response += "Sec-WebSocket-Accept: %s\x0d\x0a" % str(sec_websocket_accept, encoding="utf-8")
            if len(extensions) > 0:
                response += "Sec-WebSocket-Extensions: %s\x0d\x0a" % ', '.join(extensions)
            response += "\x0d\x0a"
            self.transport.write(response.encode("utf-8"))
            self._set_open()
            self._run_callback(self.on_open, self.peer)
            if len(self._buffer) > 0:
                self.process_frame()

    def on_open(self, addr):
        self.write_message("open %s" % json.dumps(dir(addr)))

    def on_message(self, data):
        self.write_message("on_message %s" % data)

    def on_closed(self, code=None, reason=None):
        print("on_closed: ", code, reason)

    def on_pong(self, data: bytes) -> None:
        print(self.__class__.__name__, "on_pong: ", data)

    def on_ping(self, data: bytes) -> None:
        print(self.__class__.__name__, "on_ping: ", data)

    def process_proxy_connect(self):
        pass


class WebSocketServerFactory(protocol.Factory):
    def __init__(self, request):
        self.numProtocols = 0
        self.request = request

    def buildProtocol(self, addr):
        return WebSocketServerProtocol(self, addr)


class WebSocketClientProtocol(WebSocketProtocol):
    def __init__(self, factory, compression_options=None, ping_interval=None, ping_timeout=None,
                 max_message_size=None, subprotocols=None):
        super().__init__(factory, ping_interval, ping_timeout, max_message_size, compression_options)
        self.factory = factory
        self.key = self.create_security_websocket_key()
        self.close_code = None
        self.close_reason = None
        self.subprotocols = subprotocols
        self.headers = dict()
        self.headers.update(
            {
                "Upgrade": "websocket",
                "Connection": "Upgrade",
                "Sec-WebSocket-Key": self.key,
                "User-Agent": "PythonWebSocket",
                "Sec-WebSocket-Version": "13",
                "Host": "%s" % self.options.request.netloc,
                "Origin": "http://%s" % self.options.request.netloc
            }
        )
        if subprotocols is not None:
            self.headers["Sec-WebSocket-Protocol"] = ",".join(subprotocols)
        if compression_options is not None:
            # Always offer to let the server set our max_wbits (and even though
            # we don't offer it, we will accept a client_no_context_takeover
            # from the server).
            # TODO: set server parameters for deflate extension
            # if requested in self.compression_options.
            self.headers[
                "Sec-WebSocket-Extensions"
            ] = "permessage-deflate; client_max_window_bits"

        print(factory.request.hostname, factory.request.port, factory.request.path)

    def connectionMade(self):
        self._set_connecting()
        self.start_handshake()
        try:
            self.transport.setTcpNoDelay(True)
        except:  # don't touch this! does not work: AttributeError, OSError
            # eg Unix Domain sockets throw Errno 22 on this
            pass

    def connectionLost(self, reason=protocol.connectionDone):
        print("connectionLost", reason)
        self._set_closed()

    def start_handshake(self):
        headers = ["GET %s HTTP/1.1" % self.options.request.path]
        headers.extend([f"{k}: {v}" for k, v in self.headers.items()])
        headers.append("\x0d\x0a")
        data = "\x0d\x0a".join(headers)
        self.transport.write(utf8(data))

    def _validate(self):
        subprotocol = None
        for k, v in {"upgrade": "websocket",
                     "connection": "upgrade"}.items():
            r = self.headers.get(k)
            if r is None:
                return False, None
            if v != r.lower():
                return False, None
        if self.subprotocols:
            subprotocol = self.headers.get("sec-websocket-protocol")
            if not subprotocol or subprotocol.lower() not in [s.lower() for s in self.subprotocols]:
                return False, None
        sec_websocket_accept = self.headers.get("sec-websocket-accept")
        if not sec_websocket_accept:
            return False, None

        if isinstance(sec_websocket_accept, str):
            sec_websocket_accept = sec_websocket_accept.encode('utf-8')

        hashed = self.compute_accept_value(self.key)
        success = hmac.compare_digest(hashed, sec_websocket_accept)
        if success:
            return True, subprotocol
        else:
            return False, None

    def process_handshake(self):
        end_of_header = self._buffer.find(b"\x0d\x0a\x0d\x0a")
        if end_of_header < 0:
            return
        n = end_of_header + 4
        self.http_status_line, self.headers = self._parse_headers(self._buffer[:n])
        success, subproto = self._validate()
        if not success:
            raise WebSocketError("Invalid WebSocket Header")

        self._buffer = self._buffer[n:]
        self._set_open()
        self._run_callback(self.on_open, self.options.request.netloc)

    def on_message(self, data):
        print(self.__class__.__name__, "on_message: ", data)
        self.call_later(5, self.close)

    def on_open(self, addr):
        print(self.__class__.__name__, "on_open: ", addr)
        self.periodic_ping()

    def on_closed(self, code=None, reason=None):
        print(self.__class__.__name__, "on_closed: ", code, reason)

    def on_pong(self, data: bytes) -> None:
        print(self.__class__.__name__, "on_pong: ", data)

    def on_ping(self, data: bytes) -> None:
        print(self.__class__.__name__, "on_ping: ", data)


class WebSocketClientFactory(protocol.ClientFactory):
    def __init__(self, request):
        self.numProtocols = 0
        self.request = request

    def startedConnecting(self, connector):
        print(self.__class__.__name__, 'Started to connect.')

    def buildProtocol(self, addr):
        print(self.__class__.__name__, "buildProtocol")
        return WebSocketClientProtocol(self)

    def clientConnectionLost(self, connector, reason):
        print(self.__class__.__name__, 'Lost connection.  Reason:', reason)

    def clientConnectionFailed(self, connector, reason):
        print(self.__class__.__name__, 'Connection failed. Reason:', reason)


class WebSocketServer(object):
    def __init__(self, url):
        self.request = urlparse(url)

    def run(self):
        log.startLogging(sys.stdout)
        print("run WebSocketServer")
        endpoint = endpoints.TCP4ServerEndpoint(reactor, self.request.port)
        endpoint.listen(WebSocketServerFactory(self.request))
        reactor.run()


class WebSocketClient(object):
    def __init__(self, url):
        self.request = urlparse(url)

    def run(self):
        log.startLogging(sys.stdout)
        print("run WebSocketClient")
        reactor.connectTCP(self.request.hostname, self.request.port,
                           WebSocketClientFactory(self.request))
        reactor.run()
