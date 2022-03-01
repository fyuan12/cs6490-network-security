import socket
from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
# from base64 import b64encode, b64decode

import constants as const
from crypto import sendall_wrapper, decrement_by_one

K_BOB = b'\xb0)\x1beF\xe1o\x99\xa8UT\x16\xf8\x9d+\x0e\xd7\xe4\xca\xd3\xca!\xbe\x82'

def main():
    # create a symmetric cipher that uses Bob's private key
    cipher_bob = DES3.new(K_BOB, DES3.MODE_ECB)

    # start a connect
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', const.BOB_PORT))
        s.listen()
        print("Bob waits for a connection...")
        conn, _ = s.accept()
        print("Bob is connected to Alice...")

        with conn:    
            while True:
                # receive message 1
                data_from_alice = conn.recv(const.RECV_BUF_SIZE)
                if not data_from_alice: 
                    print("Fail to receive a message from Alice")
                    break

                if data_from_alice == const.GREETING:
                    print("Bob starts Needham-Chroeder authentictation...")
                    
                    # send message 2
                    nb = get_random_bytes(const.NONCE_LEN)
                    print(f"Bob generates Nb: {nb}")
                    sendall_wrapper(conn, cipher_bob.encrypt(nb), "Bob", "Alice")

                    # receive message 5
                    data_from_alice = conn.recv(const.RECV_BUF_SIZE)
                    if not data_from_alice:
                        print("Fail to receive a message from Alice")
                        break
                    
                    ticket = data_from_alice[:const.TICKET_LEN]
                    decrypted_ticket = cipher_bob.decrypt(ticket)
                    print(f"Bob derypts the ticket: {decrypted_ticket}")

                    k_ab = decrypted_ticket[:const.KEY_LEN]
                    print(f"Bob parses shared key with Alice: {k_ab}")

                    client_id = unpad(decrypted_ticket[const.KEY_LEN:(const.KEY_LEN+const.HOST_NAME_LEN)], const.HOST_NAME_LEN)
                    print(f"Bob parses client id: {client_id}")
                    if client_id != const.ALICE_ID:
                        print("Incorrect client id. Disconneting...")
                        return

                    nb_from_alice = decrypted_ticket[(const.KEY_LEN+const.HOST_NAME_LEN):]
                    print(f"Bob parses Nb from Alice: {nb_from_alice}")
                    if nb_from_alice != nb:
                        print("Incorrect Nb. Disconneting...")
                        break
                    
                    # create a symmetric cipher that uses the shared key k_ab
                    cipher_ab = DES3.new(k_ab, DES3.MODE_ECB)
                    
                    encrpted_n2 = data_from_alice[const.TICKET_LEN:]
                    n2 = cipher_ab.decrypt(encrpted_n2)
                    print(f"Bob decrypts N2: {n2}")
                    
                    n3 = get_random_bytes(const.NONCE_LEN)
                    print(f"Bob generates N3: {n3}")

                    data_to_alice = bytearray(decrement_by_one(n2))
                    data_to_alice.extend(n3)
                    conn.sendall(cipher_ab.encrypt(data_to_alice))
                    
                    data_from_alice = conn.recv(const.RECV_BUF_SIZE)
                    if not data_from_alice:
                        print("Fail to receive a reply from Alice")
                        break
                    
                    decrypted_n3 = cipher_ab.decrypt(data_from_alice)
                    print(f"Bob decrypts N3-1 from Alice: {decrypted_n3}")

                    if decrement_by_one(n3) != decrypted_n3:
                        print("Incorrect N3. Disconneting...")
                        break
                    else:
                        print("Bob completes Needham-Chroeder authentictation...")
                        break
                        

if __name__ == '__main__':
    main()