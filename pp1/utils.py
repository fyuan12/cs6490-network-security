import socket
from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

def sendall_wrapper(socket, data, src, dst):
    socket.sendall(data)
    print(f"{src}->{dst}: {bytes(data)}")

def decrement_by_one(bytes):
    length = len(bytes)
    integer = int.from_bytes(bytes, 'big')
    integer -= 1
    return integer.to_bytes(length, 'big')

def encrypt_by_mode(mode, cipher, data):
    if mode == DES3.MODE_CBC:
        return cipher.encrypt(pad(data, DES3.block_size))
    else:
        return cipher.encrypt(data)

def decrypt_by_mode(mode, cipher, data):
    if mode == DES3.MODE_CBC:
        return unpad(cipher.decrypt(data), DES3.block_size)
    else:
        return cipher.decrypt(data)

def get_new_cipher(mode, key, iv):
    if mode == DES3.MODE_CBC:
        cipher = DES3.new(key, mode, iv=iv)
    else:
        cipher = DES3.new(key, mode)
    return cipher


# class EcbCipher:

#     def __init__(self, key):
#         self.cipher = DES3.new(key, DES3.MODE_ECB)
    
#     def encrypt(self, plaintext):
#         return self.cipher.encrypt(pad(plaintext, DES3.block_size))

#     def decrypt(self, ciphertext):
#         return unpad(self.cipher.decrypt(ciphertext), DES3.block_size)

# class CbcCipher:

#     def __init__(self, key, iv=None):
#         if iv is None:
#             self.cipher = DES3.new(key, DES3.MODE_CBC)
#         else:
#             self.cipher = DES3.new(key, DES3.MODE_CBC, iv=iv)

#     def encrypt(self, plaintext):
#         return self.cipher.encrypt(pad(plaintext, DES3.block_size))

#     def decrypt(self, ciphertext):
#         return unpad(self.cipher.decrypt(ciphertext), DES3.block_size)

# def main():
#     data = b'secret'
#     key = get_random_bytes(16)
#     cipher = CbcCipher(key)
#     iv = cipher.cipher.iv
#     ciphertext = cipher.encrypt(data)
#     cipher2 = CbcCipher(key, iv=iv)
#     plaintext = cipher2.decrypt(ciphertext)
#     print(plaintext)

# if __name__ == '__main__':
#     main()
