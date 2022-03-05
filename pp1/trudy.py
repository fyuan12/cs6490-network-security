import sys, socket, threading
from params import *
from utils import *

def main():
    if PRINT_TO_FILE:
        if not DEBUG_MODE:
            sys.stdout = open("output/ouput_trudy" + FILENAME_SUFFIX + ".txt", 'w')
        else:
            sys.stdout = open("debug/debug_trudy" + FILENAME_SUFFIX + ".txt", 'w')
    
    thread_name = threading.currentThread().name
    # retrieve the message exchanges for Trudy
    with open("a_to_b"  + FILENAME_SUFFIX + ".txt", 'rb') as f:
        a_to_b = f.read()
    with open("b_to_a"  + FILENAME_SUFFIX + ".txt", 'rb') as f:
        b_to_a = f.read()
    
    if not a_to_b or not b_to_a:
        print(f"{thread_name}\t[ERROR] Trudy does not have the messages between Alice and Bob. ")
        return
    
    print(f"{thread_name}\tTrudy sees Alice->Bob (Msg 3): {a_to_b}")
    print(f"{thread_name}\tTrudy sees Bob->Alice (Msg 4): {b_to_a}")
    print(f"{thread_name}\tTrudy starts a reflection attack on {PROTOCOL_STR}...")
    
    # start a connection to Bob
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s1:
        s1.connect(('', BOB_PORT))
        print(f"{thread_name}\tTrudy opens connection no.1 to Bob...")

        # connection 1: replay Message 3 to Bob
        sendall_wrapper(s1, a_to_b, "Trudy", "Bob", 3)
        
        # connection 1: receive message 4 from Bob
        data_from_bob_1 = recv_wrapper(s1, "Bob", "Trudy", 4)
        if not data_from_bob_1:
            return
        
        ticket_to_bob = a_to_b[:TICKET_LEN]
        print_debug_message(f"Trudy parses the ticket: {ticket_to_bob}")
        n3_from_conn1 = data_from_bob_1[NONCE_LEN:]
        print_debug_message(f"Trudy parses encrypted nonce from connection no.1: {n3_from_conn1}")

        # start another connection to Bob
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s2:
            s2.connect(('', BOB_PORT))
            print(f"{thread_name}\tTrudy opens connection no.2 to Bob...")

            # connection 2: send a spliced Message 3 to Bob
            data_to_bob_2 = bytearray(ticket_to_bob)
            data_to_bob_2.extend(n3_from_conn1)
            sendall_wrapper(s2, data_to_bob_2, "Trudy", "Bob", 3)

            # connection 2: receive another message 4 from Bob
            data_from_bob_2 = recv_wrapper(s2, "Bob", "Trudy", 4)
            if not data_from_bob_2:
                return

        # connection 1: send message 5
        data_to_bob_1 = data_from_bob_2[:NONCE_LEN]
        print_debug_message(f"Trudy parses encrypted (Nonce-1) from connection no.2: {data_to_bob_1}")
        sendall_wrapper(s1, data_to_bob_1, "Trudy", "Bob", 5)
        print(f"{thread_name}\tLast message from Alice to Bob in Hexadecimal: {data_from_bob_2[:NONCE_LEN].hex()}")

if __name__ == '__main__':
    main()