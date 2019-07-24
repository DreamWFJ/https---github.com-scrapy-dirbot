# -*- coding: utf-8 -*-
# USER: Test
# Time: 2019/5/23 14:22


import logging
import tornado.escape
import tornado.ioloop
import tornado.options
import tornado.web
import tornado.websocket
import os.path
import uuid

from tornado.options import define, options

define("port", default=8002, help="run on the given port", type=int)


class Application(tornado.web.Application):
    def __init__(self):
        handlers = [(r"/chat", ChatSocketHandler)]
        settings = dict(
            cookie_secret="__TODO:_GENERATE_YOUR_OWN_RANDOM_VALUE_HERE__",
            template_path=os.path.join(os.path.dirname(__file__), "templates"),
            static_path=os.path.join(os.path.dirname(__file__), "static"),
            debug=True,
            xsrf_cookies=True,
        )
        super(Application, self).__init__(handlers, **settings)


class ChatSocketHandler(tornado.websocket.WebSocketHandler):

    def check_origin(self, origin):
        """该方法用于不同语言调用的跨域问题"""
        return True

    def open(self):
        logging.info("new connection")

    def on_close(self):
        logging.info("connection closed")

    def on_ping(self, data: bytes) -> None:
        logging.info(f"on_ping: {data}")

    def on_pong(self, data: bytes) -> None:
        logging.info(f"on_pong: {data}")

    def on_message(self, message):
        logging.info("got message %r", message)
        self.write_message(b"hahah", binary=True)
        self.close(1001, "server close")


def main():
    tornado.options.parse_command_line()
    app = Application()
    app.listen(options.port)
    tornado.ioloop.IOLoop.current().start()


if __name__ == "__main__":
    main()
