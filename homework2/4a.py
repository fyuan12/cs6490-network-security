# Implement the RC4 code and try out the code with different key values. 
# Use the key "qwert"
# Ignore the first 512 octets, encrypt the message "This class is cool."

class RC4():

    # key-scheduling algoirthm (KSA): initalize for encrypt/decrypt
    def __init__(self, key_str):
        # initalize the 258 octets of state information
        self.state = [i for i in range(256)]
        self.x, self.y = 0, 0

        # convert key string to int array
        key = list(map(ord, list(key_str)))
        key_len = len(key_str)
        
        j = 0
        for i in range(256):
            j = (j + self.state[i] + key[i % key_len]) % 256
            self.state[i], self.state[j] = self.state[j], self.state[i]

        # discard the first 512 octes
        for i in range(512):
            self.step()

    # pseudo-random generation algorithm (PRGA): return next pseudo-random octet
    def step(self):
        self.x = (self.x + 1) % 256
        self.y = (self.y + self.state[self.x]) % 256
        self.state[self.x], self.state[self.y] = self.state[self.y], self.state[self.x]
        return self.state[(self.state[self.x] + self.state[self.y]) % 256]


def encrypt(key, plaintext, file):
    file.write(f"Encryption key: {key}\n\tPlaintext input: {plaintext}\n")
    rc4 = RC4(key)
    int_array = []
    for char in plaintext:
        int_array.append(ord(char) ^ rc4.step())
    file.write(f"\tEncrypted int array: {list(map(hex, int_array))}\n")

    # int array -> ciphertext string
    ciphertext = "".join(list(map(chr, int_array)))
    file.write(f"\tEncrypted output: {ciphertext}\n\n")
    return ciphertext


def decrypt(key, ciphertext, file):
    file.write(f"Decryption key: {key}\n\tCiphertext input: {ciphertext}\n")
    rc4 = RC4(key)
    int_array = []
    for char in ciphertext:
        int_array.append(ord(char) ^ rc4.step())
    file.write(f"\tDecrypted int array: {list(map(hex, int_array))}\n")
    plaintext = "".join(list(map(chr, int_array)))
    file.write(f"\tDecrypted output: {plaintext}\n\n")
    return plaintext


def main():
    key = "qwer"
    plaintext = "This class is cool."
    with open("4a_output.txt", "w", encoding="utf-8") as f:
        encrypted_text = encrypt(key, plaintext, f)
        decrypted_text = decrypt(key, encrypted_text, f)
        if decrypted_text == plaintext:
            f.write("Decryption indeed reverses the encryption!\n")
        else:
            f.write("Decryption does not reverse the encryption!\n")

if __name__ == "__main__":
    main()