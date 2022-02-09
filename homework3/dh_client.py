import socket
from expo import *

g, p = 1907, 784313
sa = 160031
PORT = 10000

# This is client Alice
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect(('', PORT))
    g_sa = modular_expo(g, sa, p)
    s.sendall(str(g_sa).encode('utf8'))
    
    data = s.recv(1024)
    g_sb = int(str(data, 'utf8'))
    shared_key = modular_expo(g_sb, sa, p)

    print(f"Number sent by Alice: {g_sa}")
    print(f"Alice's shared key: {shared_key}")