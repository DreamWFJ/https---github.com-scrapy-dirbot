# -*- coding: utf-8 -*-
# USER: Test
# Time: 2019/7/25 11:20

from twisted.web import resource, server
from twisted.application import internet, service, strports
from twisted.internet import protocol, reactor, defer, endpoints


class FingerService(service.Service):

    def __init__(self, filename):
        self.filename = filename

    def _read(self):
        self.users = {}
        with open(self.filename, "rb") as f:
            for line in f:
                user, status = line.split(b':', 1)
                user = user.strip()
                status = status.strip()
                self.users[user] = status
        self.call = reactor.callLater(30, self._read)

    def getUser(self, user):
        return defer.succeed(self.users.get(user, b"No such user"))

    def getUsers(self):
        return defer.succeed(self.users.keys())

    def startService(self):
        self._read()
        service.Service.startService(self)

    def stopService(self):
        service.Service.stopService(self)
        self.call.cancel()


def makeService(config):
    # finger on port 79
    s = service.MultiService()
    f = FingerService(config['file'])

    # website on port 8000
    r = resource.Resource()
    site = server.Site(r)
    j = strports.service("tcp:8000", site)
    j.setServiceParent(s)

    return s