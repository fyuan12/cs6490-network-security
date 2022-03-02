from Crypto.Cipher import DES3

EXPANDED = 0
# EXPANDED = 1
CIPHER_MODE = DES3.MODE_ECB
# CIPHER_MODE = DES3.MODE_CBC

KDC_PORT = 10000
BOB_PORT = 10001

KEY_LEN = 16
HOST_NAME_LEN = 8
NONCE_LEN = 8
TICKET_LEN = KEY_LEN + HOST_NAME_LEN + (NONCE_LEN * EXPANDED) + \
    (DES3.block_size if CIPHER_MODE == DES3.MODE_CBC else 0)
RECV_BUF_SIZE = 4096

GREETING = b'I want to talk to you'
ALICE_ID = b'1'
BOB_ID = b'2'
KDC_ID = b'3'
TRUDY_ID = b'4'

if EXPANDED:
    PROTOCOL_STR = "Expanded Needham-Chroeder authentictation " + \
        ("(CBC)" if CIPHER_MODE == DES3.MODE_CBC else "(ECB)")
else:
    PROTOCOL_STR = "Needham-Chroeder authentictation " + \
        ("(CBC)" if CIPHER_MODE == DES3.MODE_CBC else "(ECB)")