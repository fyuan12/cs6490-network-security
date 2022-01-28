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

# parameters: a plaintext string 
# returns: ciphertext as an integer array
def encrypt(key, plaintext):
    rc4 = RC4(key)
    cipher = []
    for char in plaintext:
        cipher.append(ord(char) ^ rc4.step())
    return cipher

# parameters: ciphertext as an integer array
# returns: a plaintext string
def decrypt(key, ciphertext):
    rc4 = RC4(key)
    plain = []
    for i in ciphertext:
        plain.append(i ^ rc4.step())
    return "".join(chr(i) for i in plain)

def main():
    cipher = encrypt("qwer", "This class is cool.")
    print(cipher) # decimal int array
    print(list(map(hex, cipher))) # lower hex string array
    plaintext = decrypt("qwer", cipher)
    print(plaintext)

if __name__ == "__main__":
    main()
