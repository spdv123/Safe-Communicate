# -*- coding: utf-8 -*-
import socket
from utils import Utils

HOST = '127.0.0.1'
PORT = 23333


def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # IPv4 & TCP
    msg = raw_input('Input your message:')
    # 用户输入明文
    key = raw_input('Input your AES key:')
    # 用户输入AES密钥

    cipher_msg = Utils.aes_encrypt(msg, key)
    # AES加密明文
    cipher_key = Utils.rsa_encrypt(key, 'B')
    # RSA加密AES的密钥
    sign_msg = Utils.sign(msg, 'A')
    # 签名

    text_to_send = cipher_msg + ':::' + cipher_key + ':::' + sign_msg
    # 中间插入三个冒号分割
    try:
        s.connect((HOST, PORT))
        print 'Connect OK'
        s.send(text_to_send)
        # 发送消息
        print 'Send Message:'
        print text_to_send
        data = s.recv(1024)
        print 'Server Result:'
        print data
        # 获取服务端返回结果
    except KeyboardInterrupt:
        exit(1)
    except Exception:
        pass
    s.close()


if __name__ == '__main__':
    main()
