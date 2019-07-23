# -*- coding: utf-8 -*-
# USER: Test
# Time: 2019/7/23 16:10

from tornado.websocket import websocket_connect
from tornado.ioloop import IOLoop, PeriodicCallback


def on_message_callback(response):
    print(response)


async def new_websocket_connect():
    ws = await websocket_connect("ws://127.0.0.1:8000/ws", on_message_callback=on_message_callback)
    await ws.write_message("hello")
    ws.close()


if __name__ == '__main__':
    IOLoop.current().run_sync(new_websocket_connect)

