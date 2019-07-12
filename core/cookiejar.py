# -*- coding: utf-8 -*-
# USER: Test
# Time: 2019/7/12 9:10


try:
    import Cookie
except ModuleNotFoundError:
    import http.cookies as Cookie


class SimpleCookieJar(object):
    def __init__(self):
        self.jar = dict()

    def add(self, set_cookie):
        if set_cookie:
            try:
                simple_cookie = Cookie.SimpleCookie(set_cookie)
            except AttributeError:
                simple_cookie = Cookie.SimpleCookie(set_cookie.encode('ascii', 'ignore'))
            for k, v in simple_cookie.items():
                domain = v.get("domain")

