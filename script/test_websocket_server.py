# -*- coding: utf-8 -*-
# USER: Test
# Time: 2019/7/23 16:38


from core.websocket import WebSocketServer


if __name__ == '__main__':
    WebSocketServer("ws://127.0.0.1:8002/chat").run()

