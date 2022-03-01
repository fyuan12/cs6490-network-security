import socket
from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
# from base64 import b64encode, b64decode

import constants as const
from crypto import sendall_wrapper, decrement_by_one

K_ALICE = b'\x94q\x9819\xc0\xbb#@ \xc2\xd4\xe2\x8d:\xeb\xa9\xc3\x0b\x99V\x8b\r\xf8'

def main():
    # create a symmetric cipher that uses Alice's private key
    cipher_alice = DES3.new(K_ALICE, DES3.MODE_ECB)

    # start a connection to Bob
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s_bob:
        s_bob.connect(('', const.BOB_PORT))
        print("Alice starts Needham-Chroeder authentictation...")

        # send messsage 1
        sendall_wrapper(s_bob, const.GREETING, "Alice", "Bob")

        # receive message 2
        data_from_bob = s_bob.recv(const.RECV_BUF_SIZE)
        if not data_from_bob:
            print("Fail to receive a reply from Bob")
            return

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s_kdc:
            s_kdc.connect(('', const.KDC_PORT))
            
            # send message 3
            n1 = get_random_bytes(const.NONCE_LEN)
            print(f"Alice generates N1: {n1}")
            data_to_kdc = bytearray(n1)
            data_to_kdc.extend(pad(const.ALICE_ID, const.HOST_NAME_LEN))
            data_to_kdc.extend(pad(const.BOB_ID, const.HOST_NAME_LEN))
            data_to_kdc.extend(data_from_bob)
            sendall_wrapper(s_kdc, data_to_kdc, "Alice", "KDC")

            # receive message 4
            data_from_kdc = s_kdc.recv(const.RECV_BUF_SIZE)
            if not data_from_kdc:
                print("Fail to receive a reply from KDC.")
                return
            
            decrypted_data = cipher_alice.decrypt(data_from_kdc)
            print(f"Alice decrypts message from KDC: {decrypted_data}")
            
            n1_from_kdc = decrypted_data[:const.NONCE_LEN]
            if n1_from_kdc != n1:
                print("Incorrect N1. Disconneting...")
                return
            
            i = const.NONCE_LEN
            bob_id = unpad(decrypted_data[i:(i+const.HOST_NAME_LEN)], const.HOST_NAME_LEN)
            if bob_id != const.BOB_ID:
                print("Incorrect server name. Disconneting...")
                return
            
            i += const.HOST_NAME_LEN
            k_ab = decrypted_data[i:(i+const.KEY_LEN)]
            print(f"Alice parses shared key with Bob: {k_ab}")

            i += const.KEY_LEN
            ticket_to_bob = decrypted_data[i:]
            print(f"Alice parses ticket to Bob: {ticket_to_bob}")
        
        # create a symmetric cipher that uses the shared key k_ab
        cipher_ab = DES3.new(k_ab, DES3.MODE_ECB)

        # send message 5
        n2 = get_random_bytes(const.NONCE_LEN)
        print(f"Alice generates N2: {n2}")
        data_to_bob = bytearray(ticket_to_bob)
        data_to_bob.extend(cipher_ab.encrypt(n2))
        sendall_wrapper(s_bob, data_to_bob, "Alice", "Bob")

        # receive message 6
        data_from_bob = s_bob.recv(const.RECV_BUF_SIZE)
        if not data_from_bob:
            print("Fail to receive a reply from Bob")
            return

        decrypted_data = cipher_ab.decrypt(data_from_bob)
        decrypted_n2 = decrypted_data[:const.NONCE_LEN]
        print(f"Alice decrypts N2-1 from Bob: {decrypted_n2}")

        if decrypted_n2 != decrement_by_one(n2):
            print("Incorrect N2. Disconneting...")
            return
        
        n3 = decrypted_data[const.NONCE_LEN:]
        print(f"Alice parses N3: {n3}")

        # send message 7
        sendall_wrapper(s_bob, cipher_ab.encrypt(decrement_by_one(n3)), "Alice", "Bob")
        print("Alice completes Needham-Chroeder authentictation...")

# argument: -v, verbose
# argument: -m, mode
# argument: extended or not
if __name__ == '__main__':
    main()