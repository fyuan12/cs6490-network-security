import socket
from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
# from base64 import b64encode, b64decode

import constants as const
from crypto import sendall_wrapper

K_ALICE = b'\x94q\x9819\xc0\xbb#@ \xc2\xd4\xe2\x8d:\xeb\xa9\xc3\x0b\x99V\x8b\r\xf8'
K_BOB = b'\xb0)\x1beF\xe1o\x99\xa8UT\x16\xf8\x9d+\x0e\xd7\xe4\xca\xd3\xca!\xbe\x82'
database = {const.ALICE_ID : K_ALICE, const.BOB_ID : K_BOB}

# This is server Bob
def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', const.KDC_PORT))
        s.listen()
        print("KDC waits for a connection...")
        conn, _ = s.accept()
        print("KDC starts Needham-Chroeder authentictation...")

        with conn:
            while True:
                # receive message 3
                data_from_alice = conn.recv(const.RECV_BUF_SIZE)
                if not data_from_alice:
                    print("Fail to receive a message from Alice")
                    break
                
                n1 = data_from_alice[:const.NONCE_LEN]
                print(f"KDC parses N1: {n1}")
                
                id1 = unpad(data_from_alice[const.NONCE_LEN:(const.NONCE_LEN+const.HOST_NAME_LEN)], const.HOST_NAME_LEN)
                print(f"KDC parses client ID: {id1}")
                try:
                    k_a= database[id1]
                except KeyError:
                    print("Client ID does not exist in database")
                    break
                
                id2 = unpad(data_from_alice[(const.NONCE_LEN+const.HOST_NAME_LEN):((const.NONCE_LEN+2*const.HOST_NAME_LEN))], const.HOST_NAME_LEN)
                print(f"KDC parses server ID: {id2}")
                try:
                    k_b = database[id2]
                except KeyError:
                    print("Server ID does not exist in database")
                    break
                
                # create symmetric ciphers that uses Alice and Bob's private keys
                cipher_a = DES3.new(k_a, DES3.MODE_ECB)
                cipher_b = DES3.new(k_b, DES3.MODE_ECB)

                encrypted_nb = data_from_alice[((const.NONCE_LEN+2*const.HOST_NAME_LEN)):]
                nb = cipher_b.decrypt(encrypted_nb)
                print(f"KDC decyrpts Nb: {nb}")

                # generate a random key as the shared key between Alice and Bob
                k_ab = get_random_bytes(const.KEY_LEN)
                print(f"KDC generates k_ab: {k_ab}")

                # send message 4
                ticket = bytearray(k_ab)
                ticket.extend(pad(id1, const.HOST_NAME_LEN)) # Alice
                ticket.extend(nb)
                encrypted_ticket = cipher_b.encrypt(ticket)

                data_to_alice= bytearray(n1)
                data_to_alice.extend(pad(id2, const.HOST_NAME_LEN)) # Bob
                data_to_alice.extend(k_ab)
                data_to_alice.extend(encrypted_ticket)
                sendall_wrapper(conn, cipher_a.encrypt(data_to_alice), "KDC", "Alice")
                print("KDC completes Needham-Chroeder authentictation...")
                break

if __name__ == '__main__':
    main()