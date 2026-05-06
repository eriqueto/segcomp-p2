# RSA: Creating public/private key pair
import random
import math
import hashlib
import base64

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

def xor_bytes(bytes1, bytes2):
    # implements xor operation
    ret = bytearray()
    for b1, b2 in zip(bytes1, bytes2):
        ret.append(b1 ^ b2)
    return bytes(ret)


def mgf1(seed, length, hash_func=hashlib.sha3_256):
    # https://en.wikipedia.org/wiki/Mask_generation_function
    hLen = hash_func().digest_size
    # https://www.ietf.org/rfc/rfc2437.txt
    # 1. If l > 2^32(hLen), output "mask too long" and stop.
    if length > (hLen << 32):
        raise ValueError("mask too long")
    # 2. Let T be the empty octet string.
    T = b""
    counter = 0
    while len(T) < length:
        # a. Convert counter to an octet string C of length 4 with the primitive I2OSP: C = I2OSP (counter, 4)
        C = int.to_bytes(counter, 4, "big")
        # b. Concatenate the hash of the seed Z and C to the octet string T: T = T || Hash (Z || C)
        T += hash_func(seed + C).digest()
        counter += 1
    # 4. Output the leading l octets of T as the octet string mask.
    return T[:length]


def oaep(msg_bytes):
    k = 256 # modulus size (256 bytes)
    hLen = 32 # hash length (using SHA-3 with 256 bits)
    lHash = hashlib.sha3_256(b"").digest() # no label, just empty string
    mLen = len(msg_bytes) # message size in bytes
    ps_size = k - mLen - 2 * hLen - 2 #

    PS = b"\x00" * ps_size
    DB = lHash + PS + b"\x01" + msg_bytes # data block

    seed = random.randbytes(hLen) 
    dbMask = mgf1(seed, k - hLen - 1)
    maskedDB = xor_bytes(DB, dbMask)
    seedMask = mgf1(maskedDB, hLen)
    maskedSeed = xor_bytes(seed, seedMask)

    EM = b"\x00" + maskedSeed + maskedDB # encoded message
    return EM



def generate_signature(msg_bytes, private_key):
    # Calculates SHA-3 hash and encrypts it with private key
    n, d = private_key
    
    hash_msg = hashlib.sha3_256(msg_bytes).digest()
    hash_int = int.from_bytes(hash_msg, byteorder='big')
    
    # signature: s = hash^d mod n
    signature_int = pow(hash_int, d, n)
    
    # format back to bytes and encode to base64
    n_bytes = (n.bit_length() + 7) // 8
    signature_bytes = signature_int.to_bytes(n_bytes, byteorder='big')
    
    return base64.b64encode(signature_bytes).decode('utf-8')


    
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

    # b) Asymmetric RSA encryption/decryption using OAEP (Optimal asymmetric encryption padding).
    msg = b"Hello, this is a secret test message!"
    oaep_msg = oaep(msg)
    m_int = int.from_bytes(oaep_msg, byteorder='big')
    # encryption: c = m^e mod n
    c = pow(m_int, e, n)
    encrypted_msg = c.to_bytes(256, byteorder="big")

    print("Encrypted message:", encrypted_msg)
    print("--------------------------------------------------")
    
    # Part II: Signature testing
    doc = b"Parte 2: gerando assinatura"
    signature_b64 = generate_signature(doc, private_key)
    
    print("Original document:", doc.decode('utf-8'))
    print("Generated signature (BASE64):")
    print(signature_b64)

if __name__ == "__main__":
    main()