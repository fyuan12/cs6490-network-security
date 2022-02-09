# Write a program to efficiently exponentiate big numbers modulo n
# The program should take 3 positive numbers as input: m, d, and n

# Modular exponentiation
def modular_expo(m, d, n):
    power = m
    bit = 1
    prod = 1
    while d >= bit:
        if d & bit:
            prod = (prod * power) % n
        power = (power ** 2) % n
        bit <<= 1
    return prod

def main():
    m = input("value of m: ")
    d = input("value of d: ")
    n = input("value of n: ")
    print(f"value of m^d mod n: {modular_expo(int(m), int(d), int(n))}")

if __name__ == '__main__':
    main()