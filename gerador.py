# RSA: Creating public/private key pair
import random
import math

def generate_large_prime_number():
    # Generate random 128 bytes (1024 bits) number
    # Make sure the first bit is 1 (ensure it is a 1024 bits number), 
    # Make sure it is an odd number
    num = int.from_bytes(random.randbytes(128), byteorder='big')
    num |= (1 << 1023)
    num |= 1
    return num
    
# source: https://gist.github.com/Ayrx/5884790
def miller_rabin(n, k):
    # Implementation uses the Miller-Rabin Primality Test
    # The optimal number of rounds for this test is 40
    # See http://stackoverflow.com/questions/6325576/how-many-iterations-of-rabin-miller-should-i-use-for-cryptographic-safe-primes
    # for justification

    # If number is even, it's a composite number

    if n == 2 or n == 3:
        return True

    if n % 2 == 0:
        return False

    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, s, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def get_prime_number():
    # Runs until a prime number is found
    while(True):
        num = generate_large_prime_number()
        is_prime = miller_rabin(num , 40)
        if is_prime:
            return num
        
def get_e_value(n, z):
    # Runs until it finds a value for e that has no common factors with z
    while(True):
        e = random.randrange(3, n)
        if math.gcd(e, z) == 1:
            return e
        
def get_d_value(e, z):
    # Uses the extended euclidean algorithm to find the value of d
    return pow(e, -1, z)

    
def main():
    # a) Key generation (p and q primes with at least 1024 bits)
    # 1. Choose two large prime numbers p, q.  (e.g., 1024 bits each)
    p = get_prime_number()
    q = get_prime_number()

    # 2. Compute n = pq,  z = (p-1)(q-1)
    n = p * q
    z = (p-1) * (q-1)

    # 3. Choose e (with e<n) that has no common factors with z (e, z are “relatively prime”).
    e = get_e_value(n, z)
    
    # 4. Choose d such that ed-1 is exactly divisible by z. (in other words: ed mod z  = 1 ).
    d = get_d_value(e, z)

    # 5. Public key is (n,e).  Private key is (n,d).
    public_key = (n, e)
    private_key = (n, d)


    # b) Asymmetric RSA encryption/decryption using OAEP.








if __name__ == "__main__":
    main()
