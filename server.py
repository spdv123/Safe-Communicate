# -*- coding: utf-8 -*-
from twisted.internet.protocol import Protocol, Factory
from twisted.internet import reactor
from utils import Utils


class MyProtocol(Protocol):
    def __init__(self, factory):
        self.factory = factory

    def connectionMade(self):
        print 'Connection made from', self.transport.client
        # self.transport.client is client
        # self.transport.write(s) send s to client

    def dataReceived(self, data):
        print 'Message from', self.transport.client, ':'
        data = data.strip()
        cipher_msg, cipher_key, sign_msg = data.split(':::')
        try:
            key = Utils.rsa_decrypt(cipher_key, 'B')
            msg = Utils.aes_decrypt(cipher_msg, key)
            verify_result = Utils.verify_sign(msg, sign_msg, 'A')
        except Exception:
            # 解密失败
            self.transport.write('fail')
            return
        print 'AES key:', key
        print 'Message:', msg
        print 'Verify:', verify_result
        if verify_result:
            self.transport.write('success')
        else:
            self.transport.write('fail')

    def connectionLost(self, reason):
        print 'Lost connection of', self.transport.client


class MyFactory(Factory):
    def __init__(self):
        self.numProtocols = 0

    def buildProtocol(self, addr):
        """
        Called when new client connect
        """
        return MyProtocol(self)


def main():
    factory = MyFactory()
    reactor.listenTCP(23333, factory)
    reactor.run()


if __name__ == '__main__':
    main()