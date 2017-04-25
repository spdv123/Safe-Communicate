# -*- coding: utf-8 -*-
from Crypto import Random
from Crypto.Hash import SHA
from Crypto.Cipher import PKCS1_v1_5 as Cipher_pkcs1_v1_5
from Crypto.Signature import PKCS1_v1_5 as Signature_pkcs1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
import base64


class Utils:
    def __init__(self):
        pass

    @staticmethod
    def sign(msg, who='A'):
        """
        签名函数
        :param msg: 待签名的消息
        :param who: 签名使用谁的私钥，默认是A的
        :return: 消息sha1后的签名，base64编码过
        """
        with open(who + '-private.pem') as f:
            key = f.read()
            rsa_key = RSA.importKey(key)
            signer = Signature_pkcs1_v1_5.new(rsa_key)
            digest = SHA.new()
            digest.update(msg)
            sign = signer.sign(digest)
            signature = base64.b64encode(sign)
        return signature

    @staticmethod
    def verify_sign(msg, signature, who='A'):
        """
        签名校验函数
        :param msg: 待签名校验的消息
        :param signature: 消息sha1后的签名的base64编码
        :param who: 签名校验使用谁的公钥，默认是A的
        :return: 签名结果，True是成功
        """
        try:
            with open(who + '-public.pem') as f:
                key = f.read()
                rsa_key = RSA.importKey(key)
                verifier = Signature_pkcs1_v1_5.new(rsa_key)
                digest = SHA.new()
                digest.update(msg)
                is_verify = verifier.verify(digest, base64.b64decode(signature))
            return is_verify
        except Exception:
            return False

    @staticmethod
    def rsa_encrypt(msg, who='B'):
        """
        RSA公钥加密函数
        :param msg: 待加密的消息
        :param who: 加密使用谁的公钥，默认是B
        :return: 加密结果，base64编码过
        """
        with open(who + '-public.pem') as f:
            key = f.read()
            rsa_key = RSA.importKey(key)
            cipher = Cipher_pkcs1_v1_5.new(rsa_key)
            cipher_text = base64.b64encode(cipher.encrypt(msg))
        return cipher_text

    @staticmethod
    def rsa_decrypt(cipher_text, who='B'):
        """
        RSA私钥解密函数
        :param cipher_text: 待解密的消息的base64编码
        :param who: 解密使用谁的私钥，默认是B
        :return: 解密结果，明文
        """
        try:
            with open(who + '-private.pem') as f:
                key = f.read()
                rsa_key = RSA.importKey(key)
                cipher = Cipher_pkcs1_v1_5.new(rsa_key)
                plain_text = cipher.decrypt(base64.b64decode(cipher_text), Random.new().read)
            return plain_text
        except Exception:
            print 'Warning: RSA decrypt error'
            return None

    @staticmethod
    def aes_encrypt(msg, key):
        """
        AES消息加密
        :param msg: 待加密的消息
        :param key: 加密用的key，不得长于32
        :return: 加密后的消息的base64编码
        """
        pad = 16 - len(msg) % 16
        msg += chr(pad) * pad
        if len(key) > 32:
            print 'Error: key too long'
            return None
        key += '\x00' * (32 - len(key))
        cipher = AES.new(key, AES.MODE_CBC, '\x00' * 16)
        cipher_text = cipher.encrypt(msg)
        return base64.b64encode(cipher_text)

    @staticmethod
    def aes_decrypt(cipher_text, key):
        """
        AES消息解密
        :param cipher_text: base64编码的加密消息
        :param key: 解密用的key，不得长于32
        :return: 解密后的明文消息
        """
        try:
            cipher_text = base64.b64decode(cipher_text)
            if len(key) > 32:
                print 'Error: key too long'
                return None
            key += '\x00' * (32 - len(key))
            cipher = AES.new(key, AES.MODE_CBC, '\x00' * 16)
            text = cipher.decrypt(cipher_text)
            return text[:-ord(text[-1])]
        except Exception:
            print 'Warning: AES decrypt error'
            return None
