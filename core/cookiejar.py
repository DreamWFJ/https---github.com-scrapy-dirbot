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
                if domain:
                    if not domain.startswith("."):
                        domain = "." + domain

                    cookie = self.jar.get(domain) if self.jar.get(domain) else Cookie.SimpleCookie()
                    cookie.update(simple_cookie)

                    self.jar[domain.lower()] = cookie

    def set(self, set_cookie):
        if set_cookie:
            try:
                simple_cookie = Cookie.SimpleCookie(set_cookie)
            except AttributeError:
                simple_cookie = Cookie.SimpleCookie(set_cookie.encode('ascii', 'ignore'))
            for k, v in simple_cookie.items():
                domain = v.get("domain")
                if domain:
                    if not domain.startswith("."):
                        domain = "." + domain

                    self.jar[domain.lower()] = simple_cookie

    def get(self, host):
        if not host:
            return ""
        cookies = []
        for domain, simple_cookie in self.jar.items():
            host = host.lower()
            if host.endswith(domain) or host == domain[1:]:
                cookies.append(self.jar.get(domain))
        return "; ".join(
            filter(
                None,
                [
                    "%s=%s" % (k, v.value)
                    for cookie in filter(None, sorted(cookies))
                    for k, v in sorted(cookie.items())
                ]
            )
        )
