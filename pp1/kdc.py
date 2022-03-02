import socket
from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from params import *
from utils import *

K_ALICE = b'\x98GP(P\r\x16\xde\xb1\x91\xd5\xaeH\x89\xc1\xa6'
IV_ALICE = b'v\xa0\xd1\x98C\xf8\xd6\xc1'

K_BOB = b'\xb1\xeeJ\xbbUa\xe2\xb8\xaa\x95[\r\xc6\xfb\xb0\xef'
IV_BOB = b'5"\x92\xa8\x8c\xbe\xd4\xcb'

K_AB = b'P7\x11\x0e\xf2\xb2j\t\xe2\x84S\x84\xa2\xe7\x8c\x1e'

key_database = {ALICE_ID : K_ALICE, BOB_ID : K_BOB}
iv_database = {ALICE_ID : IV_ALICE, BOB_ID : IV_BOB}

# This is server Bob
def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', KDC_PORT))
        s.listen()
        print("KDC waits for a connection...")
        conn, _ = s.accept()
        print("KDC is connected to Alice...")

        with conn:
            while True:
                # receive message 3
                data_from_alice = conn.recv(RECV_BUF_SIZE)
                if not data_from_alice:
                    print("Fail to receive a message from Alice")
                    break
                
                print(f"KDC starts {PROTOCOL_STR}...")
                n1 = data_from_alice[:NONCE_LEN]
                print(f"KDC parses N1: {n1}")
                
                id1 = unpad(data_from_alice[NONCE_LEN:(NONCE_LEN+HOST_NAME_LEN)], HOST_NAME_LEN)
                print(f"KDC parses client ID: {id1}")
                try:
                    k_a= key_database[id1]
                    iv_a = iv_database[id1]
                except KeyError:
                    print("Client ID does not exist in databases")
                    break
                
                id2 = unpad(data_from_alice[(NONCE_LEN+HOST_NAME_LEN):((NONCE_LEN+2*HOST_NAME_LEN))], HOST_NAME_LEN)
                print(f"KDC parses server ID: {id2}")
                try:
                    k_b = key_database[id2]
                    iv_b = iv_database[id2]
                except KeyError:
                    print("Server ID does not exist in databases")
                    break
                
                if EXPANDED:
                    encrypted_nb = data_from_alice[((NONCE_LEN+2*HOST_NAME_LEN)):]
                    # create a symmetric cipher that uses Bob's private key
                    cipher_bob = get_new_cipher(CIPHER_MODE, k_b, iv_b)
                    nb = decrypt_by_mode(CIPHER_MODE, cipher_bob, encrypted_nb)
                    print(f"KDC decyrpts Nb: {nb}")

                # generate a random key as the shared key between Alice and Bob
                k_ab = K_AB
                print(f"KDC generates k_ab: {k_ab}")

                # send message 4
                ticket = bytearray(k_ab)
                ticket.extend(pad(id1, HOST_NAME_LEN)) # Alice
                if EXPANDED:
                    ticket.extend(nb)

                # create a symmetric cipher that uses Bob's private key
                cipher_bob = get_new_cipher(CIPHER_MODE, k_b, iv_b)
                encrypted_ticket = encrypt_by_mode(CIPHER_MODE, cipher_bob, ticket)
                print(f"KDC encrypts ticket to Bob: {encrypted_ticket}")

                data_to_alice= bytearray(n1)
                data_to_alice.extend(pad(id2, HOST_NAME_LEN)) # Bob
                data_to_alice.extend(k_ab)
                data_to_alice.extend(encrypted_ticket)
                # create a symmetric cipher that uses Alice's private key
                cipher_alice = get_new_cipher(CIPHER_MODE, k_a, iv_a)
                sendall_wrapper(conn, encrypt_by_mode(CIPHER_MODE, cipher_alice, data_to_alice), "KDC", "Alice")
                print(f"KDC completes {PROTOCOL_STR}...")
                break

if __name__ == '__main__':
    main()