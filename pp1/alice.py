import sys, socket
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from params import *
from utils import *

# Alice's private cipher key (both ECB and CBC)
K_ALICE = b'\x98GP(P\r\x16\xde\xb1\x91\xd5\xaeH\x89\xc1\xa6'
# Alice's private cipher IV (CBC)
IV_ALICE = b'v\xa0\xd1\x98C\xf8\xd6\xc1'
# Shared cipher IV (CBC)
IV_AB = b'\xcd\xcd\xc3\xf8\xe7\xf5\xa2\xc2'

def main():
    if PRINT_TO_FILE:
        if not DEBUG_MODE:
            sys.stdout = open("output/ouput_alice" + FILENAME_SUFFIX + ".txt", 'w')
        else:
            sys.stdout = open("debug/debug_alice" + FILENAME_SUFFIX + ".txt", 'w')
    thread_name = threading.currentThread().name

    # start a connection to Bob
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s_bob:
        s_bob.connect(('', BOB_PORT))
        print(f"{thread_name}\tAlice starts {PROTOCOL_STR}...")

        if EXPANDED:
            # send messsage 1
            sendall_wrapper(s_bob, GREETING, "Alice", "Bob", 1)

            # receive message 2
            data_from_bob = recv_wrapper(s_bob, "Bob", "Alice", 2)
            if not data_from_bob:
                return

        # starts a connection to KDC
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s_kdc:
            s_kdc.connect(('', KDC_PORT))
            
            # send message 3
            n1 = get_random_bytes(NONCE_LEN)
            print_debug_message(f"Alice generates N1: {n1}")
            data_to_kdc = bytearray(n1)
            data_to_kdc.extend(pad(ALICE_ID, HOST_NAME_LEN))
            data_to_kdc.extend(pad(BOB_ID, HOST_NAME_LEN))
            if EXPANDED:
                data_to_kdc.extend(data_from_bob)
            sendall_wrapper(s_kdc, data_to_kdc, "Alice", "KDC", 3-2*(1-EXPANDED))

            # receive message 4
            data_from_kdc = recv_wrapper(s_kdc, "KDC", "Alice", 4-2*(1-EXPANDED))
            if not data_from_kdc:
                return

            cipher_alice = get_new_cipher(CIPHER_MODE, K_ALICE, IV_ALICE)
            decrypted_data = decrypt_by_mode(CIPHER_MODE, cipher_alice, data_from_kdc)
            print_debug_message(f"Alice decrypts message from KDC: {decrypted_data}")
            
            n1_from_kdc = decrypted_data[:NONCE_LEN]
            print_debug_message(f"Alice parses N1: {n1_from_kdc}")
            if n1_from_kdc != n1:
                print(f"{thread_name}\t[ERROR] Incorrect N1. Disconneting...")
                return
            
            i = NONCE_LEN
            bob_id = unpad(decrypted_data[i:(i+HOST_NAME_LEN)], HOST_NAME_LEN)
            if bob_id != BOB_ID:
                print(f"{thread_name}\t[ERROR] Incorrect server name. Disconneting...")
                return
            
            i += HOST_NAME_LEN
            k_ab = decrypted_data[i:(i+KEY_LEN)]
            print_debug_message(f"Alice parses shared key with Bob: {k_ab}")

            i += KEY_LEN
            ticket_to_bob = decrypted_data[i:]
            print_debug_message(f"Alice parses ticket to Bob: {ticket_to_bob}")

        # send message 5
        n2 = get_random_bytes(NONCE_LEN)
        print_debug_message(f"Alice generates N2: {n2}")
        data_to_bob = bytearray(ticket_to_bob)
        
        cipher_ab = get_new_cipher(CIPHER_MODE, k_ab, IV_AB)
        data_to_bob.extend(encrypt_by_mode(CIPHER_MODE, cipher_ab, n2))
        sendall_wrapper(s_bob, data_to_bob, "Alice", "Bob", 5-2*(1-EXPANDED))
        
        # receive message 6
        data_from_bob = recv_wrapper(s_bob, "Bob", "Alice", 6-2*(1-EXPANDED))
        if not data_from_bob:
            return
        
        # store the message exchange for Trudy
        if not EXPANDED:
            with open("a_to_b" + FILENAME_SUFFIX + ".txt", 'wb') as f:
                f.write(data_to_bob)
            with open("b_to_a" + FILENAME_SUFFIX + ".txt", 'wb') as f:
                f.write(data_from_bob)

        cipher_ab = get_new_cipher(CIPHER_MODE, k_ab, IV_AB)
        decrypted_data = decrypt_by_mode(CIPHER_MODE, cipher_ab, data_from_bob)
        print_debug_message(f"Alice decrypts message from Bob: {decrypted_data}")
        
        decrypted_n2 = decrypted_data[:NONCE_LEN]
        print_debug_message(f"Alice parses (N2-1): {decrypted_n2}")
        if decrypted_n2 != decrement_by_one(n2):
            print(f"{thread_name}\t[ERROR] Incorrect N2. Disconneting...")
            return
        
        n3 = decrypted_data[NONCE_LEN:]
        print_debug_message(f"Alice parses N3: {n3}")

        # send message 7
        cipher_ab = get_new_cipher(CIPHER_MODE, k_ab, IV_AB)
        data_to_bob = encrypt_by_mode(CIPHER_MODE, cipher_ab, decrement_by_one(n3))
        sendall_wrapper(s_bob, data_to_bob, "Alice", "Bob", 7-2*(1-EXPANDED))
        print(f"{thread_name}\tAlice completes {PROTOCOL_STR}...")
        print(f"{thread_name}\tLast message from Alice to Bob in Hexadecimal: {data_to_bob.hex()}")

if __name__ == '__main__':
    main()