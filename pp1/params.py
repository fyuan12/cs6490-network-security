from Crypto.Cipher import DES3

# Original or Expanded Needham-Chroeder Scheme
EXPANDED = 0
# EXPANDED = 1

# Cipher mode
CIPHER_MODE = DES3.MODE_ECB
# CIPHER_MODE = DES3.MODE_CBC

# Print out debug messages
# DEBUG_MODE = 0
DEBUG_MODE = 1

# Print to file
# PRINT_TO_FILE = 0
PRINT_TO_FILE = 1

# Constants
KDC_PORT = 10000
BOB_PORT = 10001
RECV_BUF_SIZE = 4096
KEY_LEN = 16
HOST_NAME_LEN = 8
NONCE_LEN = 8
TICKET_LEN = KEY_LEN + HOST_NAME_LEN + (EXPANDED * NONCE_LEN) + \
    (DES3.block_size if CIPHER_MODE == DES3.MODE_CBC else 0)

# Bytes and strings
GREETING = b'I want to talk to you'
ALICE_ID = b'1'
BOB_ID = b'2'
KDC_ID = b'3'
PROTOCOL_STR = ("Expanded" if EXPANDED else "") + "Needham-Chroeder authentictation " + \
    ("(CBC)" if CIPHER_MODE == DES3.MODE_CBC else "(ECB)")
FILENAME_SUFFIX = ("_expanded") if EXPANDED \
    else (("_cbc" if CIPHER_MODE == DES3.MODE_CBC else "_ecb"))