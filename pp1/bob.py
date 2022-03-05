import sys, socket, threading
from Crypto.Util.Padding import unpad
from Crypto.Random import get_random_bytes
from params import *
from utils import *

# Bob's private cipher key (both ECB and CBC)
K_BOB = b'\xb1\xeeJ\xbbUa\xe2\xb8\xaa\x95[\r\xc6\xfb\xb0\xef'
# Bob's private cipher IV (CBC)
IV_BOB = b'5"\x92\xa8\x8c\xbe\xd4\xcb'
# Shared cipher IV (CBC)
IV_AB = b'\xcd\xcd\xc3\xf8\xe7\xf5\xa2\xc2'

class ClientThread(threading.Thread):
    def __init__(self, conn):
        threading.Thread.__init__(self)
        self.conn = conn
    
    def run(self):
        thread_name = threading.currentThread().name
        print(f"{thread_name}\tBob starts {PROTOCOL_STR}...")
        
        with self.conn:
            while True:
                if EXPANDED:
                    # receive message 1
                    data_from_alice = recv_wrapper(self.conn, "Alice", "Bob", 1)
                    if not data_from_alice:
                        break
                    if data_from_alice != GREETING:
                        print(f"{thread_name}\t[ERROR] Incorrect greeting from Alice. Disconnet...")
                        break
                    
                    # send message 2
                    nb = get_random_bytes(NONCE_LEN)
                    print_debug_message(f"Bob generates Nb: {nb}")
                    cipher_bob = get_new_cipher(CIPHER_MODE, K_BOB, IV_BOB)
                    sendall_wrapper(self.conn, encrypt_by_mode(CIPHER_MODE, cipher_bob, nb), "Bob", "Alice", 2)

                # receive message 5
                data_from_alice = recv_wrapper(self.conn, "Alice", "Bob", 5-2*(1-EXPANDED))
                if not data_from_alice:
                    break

                encrypted_ticket = data_from_alice[:TICKET_LEN]
                cipher_bob = get_new_cipher(CIPHER_MODE, K_BOB, IV_BOB)
                try:
                    ticket = decrypt_by_mode(CIPHER_MODE, cipher_bob, encrypted_ticket)
                except ValueError:
                    print(f"{thread_name}\t[ERROR] Incorrect message format. Disconneting...")
                    break
                print_debug_message(f"Bob derypts the ticket: {ticket}")

                k_ab = ticket[:KEY_LEN]
                print_debug_message(f"Bob parses shared key with Alice: {k_ab}")

                client_id = unpad(ticket[KEY_LEN:(KEY_LEN+HOST_NAME_LEN)], HOST_NAME_LEN)
                print_debug_message(f"Bob parses client id: {client_id}")
                if client_id != ALICE_ID:
                    print(f"{thread_name}\t[ERROR] Incorrect client id. Disconneting...")
                    break

                if EXPANDED:
                    nb_from_alice = ticket[(KEY_LEN+HOST_NAME_LEN):]
                    print_debug_message(f"Bob parses Nb from Alice: {nb_from_alice}")
                    if nb_from_alice != nb:
                        print(f"{thread_name}\t[ERROR] Incorrect Nb. Disconneting...")
                        break
                
                encrpted_n2 = data_from_alice[TICKET_LEN:]
                cipher_ab = get_new_cipher(CIPHER_MODE, k_ab, IV_AB)
                try:
                    n2 = decrypt_by_mode(CIPHER_MODE, cipher_ab, encrpted_n2)
                except ValueError:
                    print(f"{thread_name}\t[ERROR] Incorrect message format. Disconneting...")
                    break
                print_debug_message(f"Bob decrypts N2: {n2}")
                
                # send message 6
                n3 = get_random_bytes(NONCE_LEN)
                print_debug_message(f"Bob generates N3: {n3}")
                
                data_to_encrypt = bytearray(decrement_by_one(n2))
                data_to_encrypt.extend(n3)
                cipher_ab = get_new_cipher(CIPHER_MODE, k_ab, IV_AB)
                data_to_alice = encrypt_by_mode(CIPHER_MODE, cipher_ab, data_to_encrypt)
                sendall_wrapper(self.conn, data_to_alice, "Bob", "Alice", 6-2*(1-EXPANDED))
                
                # receive message 7
                data_from_alice = recv_wrapper(self.conn, "Alice", "Bob", 7-2*(1-EXPANDED))
                if not data_from_alice:
                    break
                
                cipher_ab = get_new_cipher(CIPHER_MODE, k_ab, iv=IV_AB)
                try:
                    decrypted_n3 = decrypt_by_mode(CIPHER_MODE, cipher_ab, data_from_alice)
                except ValueError:
                    print(f"{thread_name}\t[ERROR] Incorrect message format. Disconneting...")
                    break
                print_debug_message(f"Bob decrypts (N3-1): {decrypted_n3}")
                
                if decrement_by_one(n3) != decrypted_n3:
                    print(f"{thread_name}\t[ERROR] Incorrect N3. Disconneting...")
                    break
                else:
                    print(f"{thread_name}\tBob completes {PROTOCOL_STR}...")
                    print(f"{thread_name}\tLast message from Bob to Alice in Hexadecimal: {data_to_alice.hex()}")
                    break

def main():
    if PRINT_TO_FILE:
        if not DEBUG_MODE:
            sys.stdout = open("output/ouput_bob" + FILENAME_SUFFIX + ".txt", 'w')
        else:
            sys.stdout = open("debug/debug_bob" + FILENAME_SUFFIX + ".txt", 'w')
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', BOB_PORT))
        print(f"{threading.currentThread().name}\tBob waits for a connection...")
        while True:
            s.listen()
            conn, _ = s.accept()
            new_thread = ClientThread(conn)
            new_thread.start()

if __name__ == '__main__':
    main()