# -*- coding: utf-8 -*-
import socket
from utils import Utils

HOST = '127.0.0.1'
PORT = 23333


def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # IPv4 & TCP
    msg = raw_input('Input your message:')
    key = raw_input('Input your AES key:')

    cipher_msg = Utils.aes_encrypt(msg, key)
    cipher_key = Utils.rsa_encrypt(key, 'B')
    sign_msg = Utils.sign(msg, 'A')

    text_to_send = cipher_msg + ':::' + cipher_key + ':::' + sign_msg
    try:
        s.connect((HOST, PORT))
        print 'Connect OK'
        s.send(text_to_send)
        print 'Send Message:'
        print text_to_send
        data = s.recv(1024)
        print 'Server Result:'
        print data
    except KeyboardInterrupt:
        exit(1)
    except Exception:
        pass
    s.close()


if __name__ == '__main__':
    main()
