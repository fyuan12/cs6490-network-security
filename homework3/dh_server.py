import socket
from expo import *

g, p = 1907, 784313
sb = 12077
PORT = 10000

# This is server Bob
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind(('', PORT))
    s.listen(1)
    conn, addr = s.accept()
    print("Bob connected by Alice...")

    with conn:
        while True:
            data = conn.recv(1024)
            if not data:
                break
            g_sa = int(str(data, 'utf8'))
            shared_key = modular_expo(g_sa, sb, p)
            
            g_sb = modular_expo(g, sb, p)
            conn.sendall(str(g_sb).encode('utf8'))

            print(f"Number sent by Bob: {g_sb}")
            print(f"Bob's shared key: {shared_key}")
