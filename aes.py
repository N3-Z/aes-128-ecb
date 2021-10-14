import binascii
from Crypto.Cipher import AES
import json
import sys

# encrypt:
# python aes.py [text]

# decrypt:
# copas response request, copy to file respon-json.json
# python aes.py


BLOCK_SIZE = 16
pad = lambda s: bytes(s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE), encoding='utf8')
unpad = lambda s: s[0:-ord(s[-1:])]

class AES128ECB(object):
    def __init__(self, key):
        self.key = key

    def encrypt(self, text):
        cryptor = AES.new(self.key, AES.MODE_ECB)
        ciphertext = cryptor.encrypt(pad(text))
        return binascii.b2a_hex(ciphertext)


    def decrypt(self, text):
        decode = binascii.a2b_hex(text)
        cryptor = AES.new(self.key, AES.MODE_ECB)
        plain_text = cryptor.decrypt(decode)
        return unpad(plain_text)


if __name__ == '__main__':
    aes = AES128ECB(b"key")
    
    argv = sys.argv[1:]
    if len(argv) == 1:
        text = argv[0]
        print(text)
        e = aes.encrypt(text)
        output = e.decode('utf-8').upper()
        print(output)
    else:
        f = open("respon-json.json")
        datas = json.load(f)
        f.close() 
        # can parse to json using build in json parser
        print("{")
        for i in datas:
            text = datas[i].encode('utf8')
            d = aes.decrypt(text)
            print("\t\""+i+ "\" : \""+ d.decode('utf8')+"\",")
        print("}")

