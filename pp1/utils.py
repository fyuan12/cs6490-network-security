import threading
from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
from params import RECV_BUF_SIZE, DEBUG_MODE

# socket helper functions
def sendall_wrapper(socket, data, src, dst, msg_no):
    socket.sendall(data)
    print(f"{threading.currentThread().name}\t{src}->{dst} (Msg {msg_no}): {bytes(data)}")

def recv_wrapper(socket, src, dst, msg_no):
    data = socket.recv(RECV_BUF_SIZE)
    if not data:
        print(f"{threading.currentThread().name}\t[ERROR] Fail to receive a message from {src}. Diconnecting...")
    else:
        print(f"{threading.currentThread().name}\t{src}->{dst} (Msg {msg_no}): {bytes(data)}")
    return data

# encryption helper functions
def get_new_cipher(mode, key, iv):
    if mode == DES3.MODE_CBC:
        cipher = DES3.new(key, mode, iv=iv)
    else:
        cipher = DES3.new(key, mode)
    return cipher

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

# other helper functions
def print_debug_message(message):
    if DEBUG_MODE:
        print(f"{threading.currentThread().name}\t[DEBUG] {message}")

# decrement the byte array by 1
def decrement_by_one(bytes):
    length = len(bytes)
    integer = int.from_bytes(bytes, 'big')
    integer -= 1
    return integer.to_bytes(length, 'big')