import sys, socket, threading
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from params import *
from utils import *

# Alice's private cipher key (both ECB and CBC)
K_ALICE = b'\x98GP(P\r\x16\xde\xb1\x91\xd5\xaeH\x89\xc1\xa6'
# Alice's private cipher IV (CBC)
IV_ALICE = b'v\xa0\xd1\x98C\xf8\xd6\xc1'
# Bob's private cipher key (both ECB and CBC)
K_BOB = b'\xb1\xeeJ\xbbUa\xe2\xb8\xaa\x95[\r\xc6\xfb\xb0\xef'
# Bob's private cipher IV (CBC)
IV_BOB = b'5"\x92\xa8\x8c\xbe\xd4\xcb'
# Shared cipher IV (CBC)
K_AB = b'P7\x11\x0e\xf2\xb2j\t\xe2\x84S\x84\xa2\xe7\x8c\x1e'

key_database = {ALICE_ID : K_ALICE, BOB_ID : K_BOB}
iv_database = {ALICE_ID : IV_ALICE, BOB_ID : IV_BOB}

class ClientThread(threading.Thread):
    def __init__(self, conn):
        threading.Thread.__init__(self)
        self.conn = conn
    
    def run(self):
        thread_name = threading.currentThread().name
        print(f"{thread_name}\tKDC starts {PROTOCOL_STR}...")
        with self.conn:
            while True:
                # receive message 3
                data_from_alice = recv_wrapper(self.conn, "Alice", "KDC", 3-2*(1-EXPANDED))
                if not data_from_alice:
                    break
                
                n1 = data_from_alice[:NONCE_LEN]
                print_debug_message(f"KDC parses N1: {n1}")
                
                id1 = unpad(data_from_alice[NONCE_LEN:(NONCE_LEN+HOST_NAME_LEN)], HOST_NAME_LEN)
                print_debug_message(f"KDC parses client ID: {id1}")
                try:
                    k_a= key_database[id1]
                    iv_a = iv_database[id1]
                except KeyError:
                    print(f"{thread_name}\t[ERROR] Client ID does not exist in KDC's databases")
                    break
                
                id2 = unpad(data_from_alice[(NONCE_LEN+HOST_NAME_LEN):((NONCE_LEN+2*HOST_NAME_LEN))], HOST_NAME_LEN)
                print_debug_message(f"KDC parses server ID: {id2}")
                try:
                    k_b = key_database[id2]
                    iv_b = iv_database[id2]
                except KeyError:
                    print(f"{thread_name}\t[ERROR] Server ID does not exist in KDC's databases")
                    break
                
                if EXPANDED:
                    encrypted_nb = data_from_alice[((NONCE_LEN+2*HOST_NAME_LEN)):]
                    cipher_bob = get_new_cipher(CIPHER_MODE, k_b, iv_b)
                    nb = decrypt_by_mode(CIPHER_MODE, cipher_bob, encrypted_nb)
                    print_debug_message(f"KDC decyrpts Nb: {nb}")

                # send message 4
                k_ab = get_random_bytes(KEY_LEN)
                print_debug_message(f"KDC generates k_ab: {k_ab}")

                ticket = bytearray(k_ab)
                ticket.extend(pad(id1, HOST_NAME_LEN)) # Alice
                if EXPANDED:
                    ticket.extend(nb)

                cipher_bob = get_new_cipher(CIPHER_MODE, k_b, iv_b)
                encrypted_ticket = encrypt_by_mode(CIPHER_MODE, cipher_bob, ticket)
                print_debug_message(f"KDC encrypts ticket to Bob: {encrypted_ticket}")

                data_to_alice= bytearray(n1)
                data_to_alice.extend(pad(id2, HOST_NAME_LEN)) # Bob
                data_to_alice.extend(k_ab)
                data_to_alice.extend(encrypted_ticket)
                cipher_alice = get_new_cipher(CIPHER_MODE, k_a, iv_a)
                sendall_wrapper(self.conn, encrypt_by_mode(CIPHER_MODE, cipher_alice, data_to_alice), \
                    "KDC", "Alice", 4-2*(1-EXPANDED))
                print(f"{thread_name}\tKDC completes {PROTOCOL_STR}...")
                break

def main():
    if PRINT_TO_FILE:
        if not DEBUG_MODE:
            sys.stdout = open("output/ouput_kdc" + FILENAME_SUFFIX + ".txt", 'w')
        else:
            sys.stdout = open("debug/debug_kdc" + FILENAME_SUFFIX + ".txt", 'w')
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', KDC_PORT))
        print(f"{threading.currentThread().name}\tKDC waits for a connection...")
        while True:
            s.listen()
            conn, _ = s.accept()
            new_thread = ClientThread(conn)
            new_thread.start()

if __name__ == '__main__':
    main()