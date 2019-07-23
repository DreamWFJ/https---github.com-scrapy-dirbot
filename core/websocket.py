# -*- coding: utf-8 -*-

import os
import sys
import time
import hmac
import zlib
import array
import email
import struct
import hashlib
from base64 import encodebytes
from collections import namedtuple
from urllib.parse import urlparse
from twisted.internet import protocol, reactor
from .http import to_unicode, HTTPHeaders

FrameHeader = namedtuple('FrameHeader', "fin operate_code rsv1 rsv2 rsv3 payload_length mask")

_default_max_message_size = 10 * 1024 * 1024


class WebSocketError(Exception):
    pass


class WebSocketClosedError(WebSocketError):
    """Raised by operations on a closed connection.

    .. versionadded:: 3.2
    """

    pass


class _DecompressTooLargeError(Exception):
    pass


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


def _websocket_mask_python(mask: bytes, data: bytes) -> bytes:
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


class _WebSocketParams(object):
    def __init__(self, ping_interval, ping_timeout,
                 max_message_size=_default_max_message_size, compression_options=None):
        self.ping_interval = ping_interval
        self.ping_timeout = ping_timeout
        self.max_message_size = max_message_size
        self.compression_options = compression_options


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


class WebSocketProtocol(StateMixin, protocol.Protocol):
    FIN = 0x80
    RSV1 = 0x40
    RSV2 = 0x20
    RSV3 = 0x10
    RSV_MASK = RSV1 | RSV2 | RSV3
    OPCODE_MASK = 0x0F

    def __init__(self, factory):
        self.factory = factory
        self._buffer = b''
        self._state = None
        self._compressor = None
        self._selected_subprotocol = None
        self._close_status = None
        self._close_reason = None
        self._frame_length = None
        self._frame_mask = None
        self._frame_compressed = None
        self._fragmented_message_opcode = None
        self._fragmented_message_buffer = None
        self.server_terminated = None
        self.client_terminated = None
        self._waiting = None

    def set_status(self, status=None, reason=None):
        self._close_status = status
        self._close_reason = reason

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
        sha1.update(utf8(key))
        sha1.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11")  # Magic value
        return to_unicode(encodebytes(sha1.digest()))

    def _data_received(self, data):
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
            raise Exception("invalid state")

    def _abort(self):
        self.client_terminated = True
        self.server_terminated = True
        self.transport.abortConnection()

    def close(self, code=None, reason=None):
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

    @staticmethod
    def select_subprotocol(subprotocols):
        return None

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
            # Compression flag is present in the first frame's header,
            # but we can't decompress until we have all the frames of
            # the message.
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
        if new_len > self.params.max_message_size:
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
            data = _websocket_mask_python(self._frame_mask, data)

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

        if is_final_frame:
            handled_future = self._handle_message(opcode, data)
            if handled_future is not None:
                await handled_future

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
            self.close(self.close_code)
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
        return None

    def _run_callback(self, callback, *args, **kwargs):
        """Runs the given callback with exception handling.

        If the callback is a coroutine, returns its Future. On error, aborts the
        websocket connection and returns None.
        """
        try:
            result = callback(*args, **kwargs)
        except Exception:
            self.handler.log_exception(*sys.exc_info())
            self._abort()
        else:
            return result

    def process_handshake(self):
        """
        process websocket hand shake
        :return:
        """
        raise NotImplementedError

    def process_proxy_connect(self):
        """
        process proxy connect
        :return:
        """
        raise NotImplementedError

    def on_open(self, addr):
        """
        connect build success
        :param addr:
        :return:
        """
        pass

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
        pass

    def send_message(self, data):
        """
        send message to peer
        :param data:
        :return:
        """
        pass

    @staticmethod
    def create_security_websocket_key():
        """
        创建websocket安全key
        :return:
        """
        randomness = os.urandom(16)
        return encodebytes(randomness).decode('utf-8').strip()

    def _on_frame_begin(self):
        pass

    def _on_frame_data(self):
        pass

    def _on_frame_end(self):
        pass

    def _send_frame(self, payload=b'', frame_header=None):
        pass

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
            max_message_size=self.params.max_message_size,
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
            data = mask + _websocket_mask_python(mask, data)
        frame += data
        pass

    def _write_message(self, message, binary=False):
        opcode = 0x2 if binary else 0x1
        message = utf8(message)
        assert isinstance(message, bytes)
        flags = 0
        if self._compressor:
            message = self._compressor.compress(message)
            flags |= self.RSV1
        try:
            fut = self._write_frame(True, opcode, message, flags=flags)
        except:
            raise

    def write_ping(self, data):
        assert isinstance(data, bytes)
        self._write_frame(True, 0x9, data)

    def _parse_headers(self, data):
        data_str = to_unicode(data.decode('latin1')).lstrip("\r\n")
        eol = data_str.find("\n")
        start_line = data_str[:eol].rstrip("\r")
        headers = HTTPHeaders.parse(data_str[eol:])
        return start_line, headers

    def _read_message(self, data):
        start_line_str, headers = self._parse_headers(data)


class WebSocketServerProtocol(WebSocketProtocol):
    def __init__(self, factory):
        super().__init__(factory)
        self.headers = dict()
        self.http_status_line = None

    def connectionMade(self):
        self.factory.numProtocols += 1

    def connectionLost(self, reason=protocol.connectionDone):
        self.factory.numProtocols -= 1

    def validate(self, key, subprotocols):
        subprotocol = None
        for k, v in {"upgrade": "websocket",
                     "connection": "upgrade"}.items():
            r = self.headers.get(k)
            if r is None:
                return False, None
            if v != r.lower():
                return False, None
        if subprotocols:
            subprotocol = self.headers.get("sec-websocket-protocol")
            if not subprotocol or subprotocol.lower() not in [s.lower() for s in subprotocols]:
                return False, None
        sec_websocket_accept = self.headers.get("sec-websocket-accept")
        if not sec_websocket_accept:
            return False, None
        sec_websocket_accept = sec_websocket_accept.lower()
        if isinstance(sec_websocket_accept, str):
            sec_websocket_accept = sec_websocket_accept.encode('utf-8')

        value = (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode('utf-8')
        hashed = encodebytes(hashlib.sha1(value).digest()).strip().lower()
        success = hmac.compare_digest(hashed, sec_websocket_accept)

        if success:
            return True, subprotocol
        else:
            return False, None

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
        end_of_header = self._buffer.find(b"\x0d\x0a\x0d\x0a")
        if end_of_header < 0:
            return
        n = end_of_header + 4
        self.http_status_line, self.headers = self._parse_headers(self._buffer[:n])
        try:
            self._handle_websocket_headers()
        except ValueError as e:
            self.set_status(400, e)
        else:
            subprotocol_header = self.headers.get("Sec-WebSocket-Protocol")
            if subprotocol_header:
                subprotocols = [s.strip() for s in subprotocol_header.split(",")]
            else:
                subprotocols = []
            self.selected_subprotocol = self.select_subprotocol(subprotocols)
            if self.selected_subprotocol:
                assert self.selected_subprotocol in subprotocols
                self.headers.set_header("Sec-WebSocket-Protocol", self.selected_subprotocol)

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

            self.headers.clear_header("Content-Type")
            self.set_status(101)
            self.headers.set_header("Upgrade", "websocket")
            self.headers.set_header("Connection", "Upgrade")
            self.headers.set_header("Sec-WebSocket-Accept",
                                    self.compute_accept_value(self.headers.get("Sec-Websocket-Key")))


    def start_pinging(self) -> None:
        """Start sending periodic pings to keep the connection alive"""
        assert self.ping_interval is not None
        if self.ping_interval > 0:
            self.last_ping = self.last_pong = self.current_time
            self.ping_callback = PeriodicCallback(
                self.periodic_ping, self.ping_interval * 1000
            )
            self.ping_callback.start()

    def process_proxy_connect(self):
        pass

    def on_message(self, data):
        self.transport.close()
        pass


class WebSocketServerFactory(protocol.Factory):
    def __init__(self):
        self.numProtocols = 0

    def buildProtocol(self, addr):
        pass


class WebSocketClientProtocol(WebSocketProtocol):
    def __init__(self, request, compression_options=None, ping_interval=None, ping_timeout=None,
                 max_message_size=_default_max_message_size, subprotocols=None):
        super().__init__()
        self.key = encodebytes(os.urandom(16))
        self.close_code = None
        self.close_reason = None
        self.options = _WebSocketParams(
            ping_interval=ping_interval,
            ping_timeout=ping_timeout,
            max_message_size=max_message_size,
            compression_options=compression_options,
        )
        scheme, sep, rest = request.url.partition(":")
        scheme = {"ws": "http", "wss": "https"}[scheme]
        request.url = scheme + sep + rest
        request.headers.update(
            {
                "Upgrade": "websocket",
                "Connection": "Upgrade",
                "Sec-WebSocket-Key": self.key,
                "Sec-WebSocket-Version": "13",
            }
        )
        if subprotocols is not None:
            request.headers["Sec-WebSocket-Protocol"] = ",".join(subprotocols)
        if compression_options is not None:
            # Always offer to let the server set our max_wbits (and even though
            # we don't offer it, we will accept a client_no_context_takeover
            # from the server).
            # TODO: set server parameters for deflate extension
            # if requested in self.compression_options.
            request.headers[
                "Sec-WebSocket-Extensions"
            ] = "permessage-deflate; client_max_window_bits"

    def get_handshake_headers(self, resource, host, port):
        headers = [
            "GET %s HTTP/1.1" % resource,
            "Upgrade: websocket",
            "Connection: Upgrade"
        ]
        has_header = 'header' in self.options
        host_port = "%s:%d" % (host, port)
        if "host" in self.options and self.options["host"] is not None:
            headers.append(f"Host: {self.options['host']}")
        else:
            headers.append(f"Host: {host_port}")

        if "suppress_origin" not in self.options or not self.options['suppress_origin']:
            if "origin" in self.options and self.options["origin"] is not None:
                headers.append(f"Origin: {self.options['origin']}")
            else:
                headers.append(f"Origin: http://{host_port}")
        if not has_header or 'Sec-WebSocket-Key' not in self.options['header']:
            key = self.create_security_websocket_key()
            headers.append(f"Sec-WebSocket-Key: {key}")
        else:
            key = self.options['header']['Sec-WebSocket-Key']

        if not has_header or 'Sec-WebSocket-Version' not in self.options['header']:
            headers.append("Sec-WebSocket-Version: 13")

        subprotocols = self.options.get('subprotocols')
        if subprotocols:
            headers.append(f'Sec-WebSocket-Protocol: {",".join(subprotocols)}')

        if has_header:
            header = self.options['header']
            if isinstance(header, dict):
                header = [": ".join([k, v]) for k, v in header.items() if v is not None]
            headers.extend(header)

        server_cookie = CookieJar.get(host)
        client_cookie = self.options.get('cookie')
        cookie = "; ".join(filter(None, [server_cookie, client_cookie]))
        if cookie:
            headers.append(f'Cookie: {cookie}')
        headers.append("")
        headers.append("")

        return headers, key


class WebSocketServer(object):
    def __init__(self, url):
        self.request = urlparse(url)

    def run(self):
        pass


class WebSocketClient(object):
    def __init__(self, url):
        self.request = urlparse(url)

    def run(self):
        pass
