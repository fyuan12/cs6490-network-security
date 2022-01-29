# Program a secret key encryption and decryption method
import random

class CipherProgram():
    sub_tables = []

    def __init__(self):
        
        # generate 8 unique random substitution tables and their inverses
        for i in range(8):
            sub_table = [i for i in range(256)]
            random.shuffle(sub_table)
            inverse_table = [0] * 256
            for i in range(256):
                inverse_table[sub_table[i]] = i
            self.sub_tables.append([sub_table, inverse_table])

    # int array -> 64-bit int
    def _intArrayTo64BitInt(self, arr):
        int_64bit = 0
        for i in range(8):
            int_64bit = int_64bit << 8
            int_64bit = int_64bit | arr[i]
        return int_64bit

    # 64-bit int -> int array
    def _64BitIntToIntArray(self, n):
        arr = []
        for _ in range(8):
            arr.append(n & 0xff)
            n = n >> 8
        arr.reverse()
        return arr

    def encrypt(self, password, plaintext, file):
        file.write(f"Encryption password: {password}\n\tPlaintext input: {plaintext}\n")

        # plaintext string -> int array
        int_array = list(map(ord, plaintext))
        file.write(f"\tConvert to an int array: {list(map(hex, int_array))}\n")

        # step 1. xor with password
        for i in range(8):
            int_array[i] = int_array[i] ^ ord(password[i])
        file.write(f"\tXOR: {list(map(hex, int_array))}\n")
        
        # step 2. character-by-character substitution
        for i in range(8):
            int_array[i] = self.sub_tables[i][0][int_array[i]]
        file.write(f"\tSubstitution: {list(map(hex, int_array))}\n")

        # step 3. permutation: 16 rounds of circular left shift
        int_64bit = self._intArrayTo64BitInt(int_array)
        file.write(f"\tConvert to a 64-bit integer: {hex(int_64bit)}\n")
        for i in range(16):
            int_64bit = ((int_64bit << 1) & 0xffffffffffffffff) | (int_64bit >> 63)
            file.write(f"\tPermutation round {i+1}: {hex(int_64bit)}\n")
        int_array = self._64BitIntToIntArray(int_64bit)
        file.write(f"\tConvert back to an int array: {list(map(hex, int_array))}\n")

        # int array -> ciphertext string
        ciphertext = "".join(list(map(chr, int_array)))
        file.write(f"\tCiphertext output: {ciphertext}\n\n")
        return ciphertext

    def decrypt(self, password, ciphertext, file):
        file.write(f"Decryption password: {password}\n\tCiphertext input: {ciphertext}\n")

        # ciphertext string -> int array
        int_array = list(map(ord, ciphertext))
        file.write(f"\tConvert to an int array: {list(map(hex, int_array))}\n")
        
        # step 1. permutation: 16 rounds of circular right shift
        int_64bit = self._intArrayTo64BitInt(int_array)
        file.write(f"\tConvert to a 64-bit integer: {hex(int_64bit)}\n")
        for i in range(16):
            int_64bit = (int_64bit >> 1) | ((int_64bit & 0x1) << 63)
            file.write(f"\tPermutation round {i+1}: {hex(int_64bit)}\n")
        int_array = self._64BitIntToIntArray(int_64bit)
        file.write(f"\tConvert back to an int array: {list(map(hex, int_array))}\n")

        # step 2. character-by-character substitution
        for i in range(8):
            int_array[i] = self.sub_tables[i][1][int_array[i]]
        file.write(f"\tSubstitution: {list(map(hex, int_array))}\n")
        
        # step 3. xor with password
        for i in range(8):
            int_array[i] = int_array[i] ^ ord(password[i])
        file.write(f"\tXOR: {list(map(hex, int_array))}\n")
        
        # int array -> plaintext string
        plaintext = "".join(list(map(chr, int_array)))
        file.write(f"\tPlaintext output: {plaintext}\n\n")
        return plaintext

def main():
    program = CipherProgram()
    plaintext = "INeedAnA"
    password = "cs6490hw"
    # produce an encrypted output pattern
    with open("4b_output.txt", "w", encoding="utf-8") as f:
        encrypted_text = program.encrypt(password, plaintext, f)
        # feed the encrypted output pattern to the decyption function
        decrypted_text = program.decrypt(password, encrypted_text, f)
        if decrypted_text == plaintext:
            f.write("Decryption indeed reverses the encryption!\n")
        else:
            f.write("Decryption does not reverse the encryption!\n")

if __name__ == "__main__":
    main()
