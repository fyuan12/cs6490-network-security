import socket
from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from params import *
from utils import *

K_BOB = b'\xb1\xeeJ\xbbUa\xe2\xb8\xaa\x95[\r\xc6\xfb\xb0\xef'
IV_BOB = b'5"\x92\xa8\x8c\xbe\xd4\xcb'

IV_AB = b'\xcd\xcd\xc3\xf8\xe7\xf5\xa2\xc2'

def main():
    # start a connect

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', BOB_PORT))
        s.listen()
        print("Bob waits for a connection...")
        conn, _ = s.accept()
        print("Bob is connected to Alice...")

        with conn:    
            while True:
                if EXPANDED:
                # receive message 1
                    data_from_alice = conn.recv(RECV_BUF_SIZE)
                    if not data_from_alice: 
                        print("Fail to receive a message from Alice")
                        break
                    if data_from_alice == GREETING:
                        print(f"Bob starts {PROTOCOL_STR}...")
                    
                    # send message 2
                    nb = get_random_bytes(NONCE_LEN)
                    print(f"Bob generates Nb: {nb}")
                    # create a symmetric cipher that uses Bob's private key
                    cipher_bob = get_new_cipher(CIPHER_MODE, K_BOB, IV_BOB)
                    sendall_wrapper(conn, encrypt_by_mode(CIPHER_MODE, cipher_bob, nb), "Bob", "Alice")

                # receive message 5
                data_from_alice = conn.recv(RECV_BUF_SIZE)
                if not data_from_alice:
                    print("Fail to receive a message from Alice")
                    break
                if not EXPANDED:
                    print(f"Bob starts {PROTOCOL_STR}...")

                encrypted_ticket = data_from_alice[:TICKET_LEN]
                cipher_bob = get_new_cipher(CIPHER_MODE, K_BOB, IV_BOB)
                ticket = decrypt_by_mode(CIPHER_MODE, cipher_bob, encrypted_ticket)
                print(f"Bob derypts the ticket: {ticket}")

                k_ab = ticket[:KEY_LEN]
                print(f"Bob parses shared key with Alice: {k_ab}")

                client_id = unpad(ticket[KEY_LEN:(KEY_LEN+HOST_NAME_LEN)], HOST_NAME_LEN)
                print(f"Bob parses client id: {client_id}")
                if client_id != ALICE_ID:
                    print("Incorrect client id. Disconneting...")
                    return

                if EXPANDED:
                    nb_from_alice = ticket[(KEY_LEN+HOST_NAME_LEN):]
                    print(f"Bob parses Nb from Alice: {nb_from_alice}")
                    if nb_from_alice != nb:
                        print("Incorrect Nb. Disconneting...")
                        break
                
                encrpted_n2 = data_from_alice[TICKET_LEN:]
                # create a symmetric cipher that uses the shared key k_ab
                cipher_ab = get_new_cipher(CIPHER_MODE, k_ab, IV_AB)
                n2 = decrypt_by_mode(CIPHER_MODE, cipher_ab, encrpted_n2)
                print(f"Bob decrypts N2: {n2}")
                
                n3 = get_random_bytes(NONCE_LEN)
                print(f"Bob generates N3: {n3}")

                # send message 6
                data_to_encrypt = bytearray(decrement_by_one(n2))
                data_to_encrypt.extend(n3)
                # create a symmetric cipher that uses the shared key k_ab
                cipher_ab = get_new_cipher(CIPHER_MODE, k_ab, IV_AB)
                data_to_alice = encrypt_by_mode(CIPHER_MODE, cipher_ab, data_to_encrypt)
                sendall_wrapper(conn, data_to_alice, "Bob", "Alice")
                
                # receive message 7
                data_from_alice = conn.recv(RECV_BUF_SIZE)
                if not data_from_alice:
                    print("Fail to receive a reply from Alice")
                    break
                
                # create a symmetric cipher that uses the shared key k_ab
                cipher_ab = get_new_cipher(CIPHER_MODE, k_ab, iv=IV_AB)
                decrypted_n3 = decrypt_by_mode(CIPHER_MODE, cipher_ab, data_from_alice)
                print(f"Bob decrypts N3-1 from Alice: {decrypted_n3}")
                if decrement_by_one(n3) != decrypted_n3:
                    print("Incorrect N3. Disconneting...")
                    break
                else:
                    print(f"Bob completes {PROTOCOL_STR}...")
                    print(f"\nLast message from Bob to Alice in Hexadecimal: {data_to_alice.hex()}")
                    break
                        

if __name__ == '__main__':
    main()