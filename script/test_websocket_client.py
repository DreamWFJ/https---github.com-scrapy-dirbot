# -*- coding: utf-8 -*-
# USER: Test
# Time: 2019/7/24 10:23


from core.websocket import WebSocketClient


if __name__ == '__main__':
    WebSocketClient("ws://127.0.0.1:8002/chat").run()
