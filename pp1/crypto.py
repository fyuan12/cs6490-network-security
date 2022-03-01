import socket
from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode

def sendall_wrapper(socket, data, src, dst):
    socket.sendall(data)
    print(f"{src}->{dst}: {bytes(data)}")

def decrement_by_one(bytes):
    length = len(bytes)
    integer = int.from_bytes(bytes, 'big')
    integer -= 1
    return integer.to_bytes(length, 'big')

class EcbCipher:

    def __init__(self, key):
        self.cipher = DES3.new(key, DES3.MODE_ECB)
    
    def encrypt(self, plaintext):
        return self.cipher.encrypt(pad(plaintext, DES3.block_size))

    def decrypt(self, ciphertext):
        return unpad(self.cipher.decrypt(ciphertext), DES3.block_size)

class CbcCipher:

    def __init__(self, key, iv=None):
        if iv is None:
            self.cipher = DES3.new(key, DES3.MODE_CBC)
        else:
            self.cipher = DES3.new(key, DES3.MODE_CBC, iv=iv)

    def encrypt(self, plaintext):
        return self.cipher.encrypt(pad(plaintext))

    def decrypt(self, ciphertext):
        return unpad(self.cipher.decrypt(ciphertext))

def main():
    data = b'secret'
    key = get_random_bytes(16)
    cipher = EcbCipher(key)
    ciphertext = cipher.encrypt(data)
    plaintext = cipher.decrypt(ciphertext)
    print(plaintext)

if __name__ == '__main__':
    main()
