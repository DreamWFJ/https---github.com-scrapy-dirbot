# -*- coding: utf-8 -*-

from collections import namedtuple


FrameHeader = namedtuple('FrameHeader', "fin operate_code rsv1 rsv2 rsv3 payload_length mask")


class StateMixin:
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


class WebSocketProtocol(StateMixin):
    def __init__(self):
        self._buffer = b''
        self._state = None

    def _data_received(self, data):
        """
        receive data
        :param data:
        :return:
        """
        self._buffer += data
        if self._is_open:
            pass
        elif self._is_proxy_connecting:
            self.process_proxy_connect()
        elif self._is_connecting:
            self.process_handshake()
        elif self._is_closed:
            pass
        elif self._is_closing:
            pass
        else:
            pass

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

    def close(self, abort=False):
        """
        close connection
        :param abort:
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

    def _on_frame_begin(self):
        pass

    def _on_frame_data(self):
        pass

    def _on_frame_end(self):
        pass

    def _send_frame(self, payload=b'', frame_header=None):
        pass


class WebSocketServerProtocol(WebSocketProtocol):
    def process_handshake(self):
        pass

    def process_proxy_connect(self):
        pass

    def on_message(self, data):
        pass
