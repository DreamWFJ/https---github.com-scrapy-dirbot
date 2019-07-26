# -*- coding: utf-8 -*-


from twisted.web import resource, server
from twisted.application import internet, service
from twisted.internet import reactor


class Root(resource.Resource):
    isLeaf = True

    def render(self, request):
        if request.method == "GET":
            return f"<html>Hello, {self.__class__.__name__} GET!</html>"
        elif request.method == "POST":
            return f"<html>Hello, {self.__class__.__name__} GET!</html>"

    def getChild(self, path, request):
        if path == "":
            return self
        return resource.Resource.getChild(self, path, request)


class Simple(resource.Resource):
    def render(self, request):
        if request.method == "GET":
            return f"<html>Hello, {self.__class__.__name__} GET!</html>"
        elif request.method == "POST":
            return f"<html>Hello, {self.__class__.__name__} GET!</html>"


if __name__ == "__main__":
    from twisted.web import server
    from twisted.internet import reactor

    root = Root()
    root.putChild('simple', Simple())
    site = server.Site(root)
    reactor.listenTCP(8080, site)
    reactor.run()
