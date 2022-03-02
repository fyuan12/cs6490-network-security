import socket
from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from params import *
from utils import *

# TODO: Work on Trudy's program

K_ALICE = b'\x94q\x9819\xc0\xbb#@ \xc2\xd4\xe2\x8d:\xeb\xa9\xc3\x0b\x99V\x8b\r\xf8'
IV_ALICE = b'v\xa0\xd1\x98C\xf8\xd6\xc1'
IV_AB = b'\xcd\xcd\xc3\xf8\xe7\xf5\xa2\xc2'

MSG3 = b''
MSG4 = b''

def main():
    # start a connection to Bob
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s_bob:
        s_bob.connect(('', BOB_PORT))
        print(f"Alice starts {PROTOCOL_STR}...")

        if EXPANDED:
            # send messsage 1
            sendall_wrapper(s_bob, GREETING, "Alice", "Bob")

            # receive message 2
            data_from_bob = s_bob.recv(RECV_BUF_SIZE)
            if not data_from_bob:
                print("Fail to receive a reply from Bob")
                return

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s_kdc:
            s_kdc.connect(('', KDC_PORT))
            
            # send message 3
            n1 = get_random_bytes(NONCE_LEN)
            print(f"Alice generates N1: {n1}")
            data_to_kdc = bytearray(n1)
            data_to_kdc.extend(pad(ALICE_ID, HOST_NAME_LEN))
            data_to_kdc.extend(pad(BOB_ID, HOST_NAME_LEN))
            if EXPANDED:
                data_to_kdc.extend(data_from_bob)
            sendall_wrapper(s_kdc, data_to_kdc, "Alice", "KDC")

            # receive message 4
            data_from_kdc = s_kdc.recv(RECV_BUF_SIZE)
            if not data_from_kdc:
                print("Fail to receive a reply from KDC.")
                return
            
            cipher_alice = get_new_cipher(CIPHER_MODE, K_ALICE, IV_ALICE)
            decrypted_data = decrypt_by_mode(CIPHER_MODE, cipher_alice, data_from_kdc)
            print(f"Alice decrypts message from KDC: {decrypted_data}")
            
            n1_from_kdc = decrypted_data[:NONCE_LEN]
            print(f"Alice parses N1: {n1_from_kdc}")
            if n1_from_kdc != n1:
                print("Incorrect N1. Disconneting...")
                return
            
            i = NONCE_LEN
            bob_id = unpad(decrypted_data[i:(i+HOST_NAME_LEN)], HOST_NAME_LEN)
            if bob_id != BOB_ID:
                print("Incorrect server name. Disconneting...")
                return
            
            i += HOST_NAME_LEN
            k_ab = decrypted_data[i:(i+KEY_LEN)]
            print(f"Alice parses shared key with Bob: {k_ab}")

            i += KEY_LEN
            ticket_to_bob = decrypted_data[i:]
            print(f"Alice parses ticket to Bob: {ticket_to_bob}")

        # send message 5
        n2 = get_random_bytes(NONCE_LEN)
        print(f"Alice generates N2: {n2}")
        data_to_bob = bytearray(ticket_to_bob)
        # create a symmetric cipher that uses the shared key k_ab
        cipher_ab = get_new_cipher(CIPHER_MODE, k_ab, IV_AB)
        data_to_bob.extend(encrypt_by_mode(CIPHER_MODE, cipher_ab, n2))
        sendall_wrapper(s_bob, data_to_bob, "Alice", "Bob")

        # receive message 6
        data_from_bob = s_bob.recv(RECV_BUF_SIZE)
        if not data_from_bob:
            print("Fail to receive a reply from Bob")
            return

        # create a symmetric cipher that uses the shared key k_ab
        cipher_ab = get_new_cipher(CIPHER_MODE, k_ab, IV_AB)
        decrypted_data = decrypt_by_mode(CIPHER_MODE, cipher_ab, data_from_bob)
        print(f"Alice decrypts message from Bob: {decrypted_data}")
        decrypted_n2 = decrypted_data[:NONCE_LEN]
        print(f"Alice parses N2-1: {decrypted_n2}")

        if decrypted_n2 != decrement_by_one(n2):
            print("Incorrect N2. Disconneting...")
            return
        
        n3 = decrypted_data[NONCE_LEN:]
        print(f"Alice parses N3: {n3}")

        # send message 7
        # create a symmetric cipher that uses the shared key k_ab
        cipher_ab = get_new_cipher(CIPHER_MODE, k_ab, IV_AB)
        data_to_bob = encrypt_by_mode(CIPHER_MODE, cipher_ab, decrement_by_one(n3))
        sendall_wrapper(s_bob, data_to_bob, "Alice", "Bob")
        print(f"Alice completes {PROTOCOL_STR}...")
        print(f"\nLast message from Alice to Bob in Hex: {data_to_bob.hex()}")

# argument: -v, verbose
# argument: -m, mode
# argument: extended or not
if __name__ == '__main__':
    main()