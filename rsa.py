#! /usr/bin/env python3

"""RSA key exchange protocol by Brendan Sweeney, CSS 527, Assignment 2.

2-part implementation of RSA public key exchange and secure symmetric session
key exchange protocol. The first part is a server, Bob, that listens for a
request for a public key. The second part, Alice, is a client that sends a
public key to initiate a request for Bob's public key. Once both parties have
generated their private/public key pairs and exchanged public keys, Alice
generates a symmetric key, nonces it, signs the message, encrypts it with Bob's
public key, then sends the encrypted message to Bob. Bob decrypts the message,
increments the nonce, encrypts the result with the session key, then sends the
result to Alice for verification. Finally, Alice prints out the original nonce
and the decrypted message from Bob for comparison.

Keyword arguments:
party -- Required. The party to be represented by this instance of the program.
         Must be either alice or bob.
host -- The host machine of the server process, Bob. For Bob, this is the local
        interface on which the program will listen for a connection. For Alice,
        this is the machine at which a connection with Bob will be attempted.
        Defaults to localhost.
port -- Network port over which the protocol will be performed. For Bob, this is
        the port on which the program will listen for a connection. For Alice,
        this is the port to which a connection with Bob will be attempted.
        Defaults to DEFAULT_PORT (defined below).
"""

from Crypto.Cipher import Blowfish
from Crypto import Random
from math import ceil
from pickle import dumps, loads
from struct import pack
from time import sleep
import random
import socket
import sys

# Connection defaults
BUFFER_SIZE = 1024
DEFAULT_AHOST = 'localhost'
DEFAULT_BHOST = 'localhost'
DEFAULT_PORT = 51836
MIN_PORT = 1024
MAX_PORT = 65535

# Key constants

# Encryption value for public keys
E_VALUE = 2**16 + 1
# Length of asymmetric key modulus, in bits
KEY_LENGTH = 48
# Length of symmetric key, in bits
BF_KEY_LENGTH = 128
# Size of symmetric encryption block, in bytes
BS = Blowfish.block_size
# Maximum length of a message before appending a nonce, in bits
MSG_LENGTH = KEY_LENGTH - 16
# Length of the random nonce, in bits
NONCE_LENGTH = 14
# Bit mask for extracting a signable portion of a message from a longer value
MSG_MASK = 2**MSG_LENGTH - 1
# Bit mask for extracting a nonce from a longer value
NONCE_MASK = 2**NONCE_LENGTH - 1
# Bit mask for ensuring prime candidates are odd and resonably large
PRIME_MASK = 2**(KEY_LENGTH // 2 - 1) + 2**(KEY_LENGTH // 2 - 2) + 2**0
# Miller-Rabin confidence value
K = 3
# Indexes
PRIV_KEY_IND = 0
PUB_KEY_IND = 1
# Indexes specific to private key
P_IND = 0
Q_IND = 1
DP_IND = 2
DQ_IND = 3
Q_INV_IND = 4
# Indexes specific to public key
N_IND = 0
E_IND = 1



def _alice(host, port):
    """Alice initiates a public key exchange and encrypted session with Bob.

    After contacting Bob, Alice generates an RSA key pair and some other values
    for encrypted communication. She sends the public portion of the RSA key to
    Bob and accepts his public key in response. Using the keys, she signs and
    encrypts an integer that represents a symmetric block cipher key and a
    nonce. She sends the resulting value to Bob and waits for Bob to return the
    nonce incremented by one and encrypted with the symmetric key. She then
    decrypts the message from Bob, compares it to the expected value and,
    finally, prints a brief summary of the results.


    Keyword arguments:
    host -- The host machine of the server process, Bob. This is the machine at
            which a connection with Bob will be attempted. Defaults to
            localhost.
    port -- Network port over which the protocol will be performed. This is the
            port to which a connection with Bob will be attempted. Defaults to
            DEFAULT_PORT (defined above).
    """
    msg = []
    msgSigned = []
    msgCipher = []

    # Establish connection to Bob before spending time on crypto operations
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))

    print("Alice generating RSA key pair...")
    aliceKey = gen_rsa()
    print("Alice done generating RSA key pair.")
    generator = random.SystemRandom()
    sessKey = generator.getrandbits(BF_KEY_LENGTH)
    nonce = generator.getrandbits(NONCE_LENGTH)

    # Break the session key into parts small enough to sign with the RSA key
    for i in reversed(range(ceil(BF_KEY_LENGTH / MSG_LENGTH))):
        # Isolate the chunk of interest
        part = sessKey >> (MSG_LENGTH * i)
        part = part & MSG_MASK
        # Append the nonce
        part = part << NONCE_LENGTH
        part = part | nonce
        # Add one signable chunk of plain text + nonce to initial message
        msg.append(part)

    print("Alice processing message in", len(msg), "parts.")

    # Sign each part of the message
    for part in msg:
        print("  Alice signing...")
        msgSigned.append(rsa_sign(part, aliceKey[PRIV_KEY_IND]))

    print("Alice done signing.")

    # XCHG 1 - Send public key to Bob
    s.send(dumps(aliceKey[PUB_KEY_IND]))

    # XCHG 2 - Get public key from Bob
    bobPubKey = loads(s.recv(BUFFER_SIZE))

    # Use Bob's public key to encrypt each part of the signed message
    for sig in msgSigned:
        print("  Alice encrypting...")
        msgCipher.append(rsa_encrypt(sig, bobPubKey))

    print("Alice done encrypting.")

    # XCHG 3 - Send session key to Bob
    s.send(dumps(msgCipher))

    # XCHG 4 - Get encrypted nonce + 1 from Bob
    reply = loads(s.recv(BUFFER_SIZE))
    s.close()

    # Convert session key to usable Blowfish key and setup decryption cipher
    bfKey = sessKey.to_bytes((sessKey.bit_length() // 8) + 1, byteorder='big')
    cipher = Blowfish.new(bfKey, Blowfish.MODE_CBC, reply[0])

    # Extract the encrypted part of the message and decrypt it
    deciphered = cipher.decrypt(reply[1])

    # Convert reply to an integer and check with expected value
    rshift = (BS - ceil(NONCE_LENGTH / 8)) * 8
    bobNonce = int.from_bytes(deciphered, byteorder='big') >> rshift

    sleep(1)
    print("\nBob replied with  :", bobNonce)
    print("Expected reply is :", nonce + 1)
    success = bobNonce == (nonce + 1) % (NONCE_MASK + 1)
    print("Success!" if success else "Something went wrong.")



def _bob(host, port):
    """Bob listens for Alice to initiate a public key exchange.

    While waiting to be contacted by Alice, Bob generates an RSA key pair and
    some other values for encrypted communication. Once Alice sends her public
    key, Bob accepts it and sends his public key in response. Using the keys, he
    decrypts and verifies the signature on an integer that should represent a
    symmetric block cipher key and a nonce. He increments the nonce by one,
    encrypts that with the symmetric key, sends the resulting ciphertest to
    Alice, then closes the network connection.

    Keyword arguments:
    host -- The listening interface of the server process, Bob. This is the
            local network interface on which the program will listen for a
            connection. Defaults to localhost.
    port -- Network port over which the protocol will be performed. This is the
            port on which the program will bind to listen for a connection.
            Defaults to DEFAULT_PORT (defined above).
    """
    done = False
    sessKey = 0
    msgSigned = []
    msg = []

    # Setup network socket and wait for Alice to connect
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((host, port))
    s.listen(1)

    iv = Random.new().read(BS)
    print("Bob generating RSA key pair...")
    bobKey = gen_rsa()
    print("Bob done generating RSA key pair.")
    conn, addr = s.accept()

    # Loop only used by convention; closes after single run through protocol
    while not done:
        # XCHG 1 - Get public key from Alice
        alicePubKey = loads(conn.recv(BUFFER_SIZE))

        # XCHG 2 - Send public key to Alice
        conn.send(dumps(bobKey[PUB_KEY_IND]))

        # XCHG 3 - Get session key from Alice
        msgCipher = loads(conn.recv(BUFFER_SIZE))

        print("\nBob processing message in", len(msgCipher), "parts.")
        # Decrypt each part of the ciphertext message
        for ciph in msgCipher:
            print("  Bob decrypting...")
            msgSigned.append(rsa_decrypt(ciph, bobKey[PRIV_KEY_IND]))

        print("Bob done decrypting.")

        # Verify the signatures of the signed message
        for sig in msgSigned:
            print("  Bob verifying...")
            msg.append(rsa_verify(sig, alicePubKey))

        print("Bob done verifying.")

        # Extract the nonce from the first segment of the plain message
        nonce = msg[0] & NONCE_MASK

        # Reconstruct the session key from all parts and verify the nonce
        for part in msg:
            # Make room for the new part and add it to the end of sessKey
            sessKey = sessKey << (MSG_LENGTH + NONCE_LENGTH)
            sessKey = sessKey | part
            if nonce != sessKey & NONCE_MASK: print("nonce mismatch!")
            # Remove the nonce portion of the message part
            sessKey = sessKey >> NONCE_LENGTH

        # Update the nonce and prepare it, and the symmetric key, for encryption
        nonce = (nonce + 1) % (NONCE_MASK + 1)
        plaintext = nonce.to_bytes((nonce.bit_length() // 8) + 1,
                                    byteorder='big')
        bfKey = sessKey.to_bytes((sessKey.bit_length() // 8) + 1,
                                    byteorder='big')

        # Setup Blowfish encryption cipher and padding, then encrypt a message
        cipher = Blowfish.new(bfKey, Blowfish.MODE_CBC, iv)
        plen = BS - divmod(len(plaintext),BS)[1]
        padding = [plen]*plen
        padding = pack('b'*plen, *padding)
        reply = [iv, cipher.encrypt(plaintext + padding)]

        # XCHG 4 - Send encrypted nonce + 1 to Alice
        conn.send(dumps(reply))
        done = True

    conn.close()



def gen_rsa():
    """Generate a public/private key pair modeled on the RSA standard.

    Returns a 2-element list of integer lists. The sublist of the first element
    holds the integers for the private portion of the key. The sublist of the
    second element holds the integers for the public portion of the key. Due to
    a lack of optimization, this function should not be used with arbitray key
    lengths, so it relies on its callees to use the modestly-sized KEY_LENGTH
    (defined above) of 48 bits.
    """
    # Public and private exponents
    e = E_VALUE
    d = None

    # Ensure d is the multiplicative inverse of e (modulo φ(n)), once calculated
    while d == None:
        p = gen_prime()
        q = p

        # Ensure p and q are distinct
        while q == p:
            q = gen_prime()

        # Calculate the modulous and, from it, the private exponent d
        n = p * q
        tot_n = (p - 1) * (q - 1)
        d = inverse(e, tot_n)

    # Setup private key values for Chinese remainder calculations
    dP = d % (p - 1)
    dQ = d % (q - 1)
    qInv = inverse(q, p)

    return [[p, q, dP, dQ, qInv], [n, e]]



def gen_prime():
    """Generate a number that is statistically likely to be prime.

    Returns an integer that is probably prime. A randome number is generated
    then bitmasked to ensure it is odd and of sufficient size. In the interest
    of speed, rollover is not checked and may lead to a number of greater size
    than anticipated. Candidates are run through the Miller-Rabin primality test
    until one passes as a likely prime.
    """
    generator = random.SystemRandom()
    # Product of 2 primes should produce a number of KEY_LENGTH bits
    candidate = generator.randrange(2**(KEY_LENGTH // 2)) | PRIME_MASK
    print("  Testing primality...")
    foundPrime = miller_rabin(candidate, K)

    # Check consecutive odd numbers until a likely prime is found
    while not foundPrime:
        # Ensure desired bounds of new candidate
        candidate = (candidate - 2) | PRIME_MASK
        foundPrime = miller_rabin(candidate, K)

    print("\n  Done - probably prime.")
    return candidate



def miller_rabin(n, k):
    """Probabilistically test the primality of an odd integer.

    Returns False if the input integer is definitely composite; returns True if
    the input integer is likely a prime number. Uses the Miller-Rabin primality
    test to efficiently determine whether an odd integer has a high probability
    of being prime. Multiple trials can be run to increase the confidence of
    primality without affecting performance for composite numbers, as the
    algorithm terminates as soon as is ascertains compositeness.

    Keyword arguments:
    n -- An odd integer of arbitrary size. Large numbers may be very slow.
    k -- Number of times to run the test on a single number.
    """
    s = 0
    d = n - 1

    # Only perform the test on odd numbers greater than 2
    if n < 3 or n % 2 == 0: return False

    # Find s and d such that n - 1 == 2^s * d, d % 2 != 0
    while d % 2 == 0:
        s += 1
        # d is even, floor division used to prevent conversion to float
        d = d // 2

    # Witness loop for primality of n
    for i in range(k):
        a = random.randrange(2, n - 1)
        x = modular_pow(a, d, n)

        # Likely prime; done with this run through the loop
        if x == 1 or x == n - 1: continue

        for j in range(s - 1):
            x = modular_pow(x, 2, n)
            if x == 1:
                print('.', end='')
                sys.stdout.flush()
                # n is composite
                return False
            if x == n - 1: break
        else:
            # Inner loop exausted; n is composite
            print('.', end='')
            sys.stdout.flush()
            return False

    # n survived k runs through the test; probably prime
    return True



def modular_pow(base, exponent, modulus):
    """Use modular exponentiation to calculate number to high powers.

    Adapted from Wikipedia: Modular exponentiation -
        http://en.wikipedia.org/wiki/Modular_exponentiation

    Returns the result of raising an integer to a high power over a given
    modulus. Rather than calculate the full power and divide the resulting
    number by the modulus, this algorithm applies the modulus to a running
    value multiplied by the base integer a number of times, determined by the
    exponent.

    Keyword arguments:
    base -- An integer to be raised to a desired power, modulo a given modulus.
    exponent -- An integer power to which to raise the base.
    modulus -- An integer modulus to apply to the result of the power operation.
    """
    c = 1

    for e_prime in range(exponent):
        c = (c * base) % modulus

    return c



def inverse(a, n):
    """Find the multiplicative inverse of one number over a given range.

    Adapted from Wikipedia: Extended Euclidian Algorithm -
        http://en.wikipedia.org/wiki/Extended_Euclidean_algorithm

    Returns the multiplicative inverse of a over the finite range n. The result
    is a number which, when multiplied by a, will return 1 over range n.

    Keyword arguments:
    a -- The integer whose multiplicative inverse should be found.
    n -- A positive integer defining the numeric range to evaluate.
    """
    t = 0
    newt = 1
    r = n
    newr = a

    while newr != 0:
        quotient = r // newr
        t, newt = newt, t - quotient * newt
        r, newr = newr, r - quotient * newr

    if r > 1: return None
    if t < 0: t = t + n

    return t



def rsa_encrypt(msg, pubKey):
    """Encrypt a short message with an RSA public key.

    Returns an integer representing the ciphertext of the input message. The
    message must be represented as an integer that is smaller than the modulus
    of the key. Assuming sufficient key size, the message should only be
    recoverable in any reasonable amout of time by decrypting the ciphertext
    with the private portion of the provided public key.

    Keyword arguments:
    msg -- A positive integer less than the modulus of the provided key.
    pubKey -- A 2-integer list containing the modulus and public exponent of an
              RSA key.
    """
    if msg > pubKey[N_IND]:
        print("Message too long to encrypt with", KEY_LENGTH, "bit key.")

    # Always attempt encryption, even if it will return a bad value
    return modular_pow(msg, pubKey[E_IND], pubKey[N_IND])



def rsa_decrypt(cipherText, privKey):
    """Decrypt some short ciphertext with an RSA private key.

    Returns an integer representing the original message of the ciphertext. The
    ciphertext must have been created with the corresponding public key for the
    message to be properly recovered.

    Keyword arguments:
    cipherText -- A positive integer that resulted from RSA encryption.
    privKey -- A 5-integer list containing the private elements of an RSA key.
    """
    m1 = modular_pow(cipherText, privKey[DP_IND], privKey[P_IND])
    m2 = modular_pow(cipherText, privKey[DQ_IND], privKey[Q_IND])
    h = privKey[Q_INV_IND] * (m1 - m2) % privKey[P_IND]
    m = m2 + h * privKey[Q_IND]

    return m



def rsa_sign(msg, privKey):
    """Sign a short message by encrypting it with an RSA private key.

    Returns an integer representing the ciphertext of the input message. The
    message must be represented as an integer that is smaller than the modulus
    of the key. Assuming sufficient key size, the message should only be
    recoverable in any reasonable amout of time by decrypting the ciphertext
    with the public portion of the provided private key, allowing for strong
    authentication of the source of the message.

    Keyword arguments:
    msg -- A positive integer less than the modulus of the provided key.
    privKey -- A 5-integer list containing the private elements of an RSA key.
    """
    return rsa_decrypt(msg, privKey)



def rsa_verify(sig, pubKey):
    """Verify the source of a message by decrypting it with an RSA public key.

    Returns an integer representing the original message of the ciphertext. The
    ciphertext must have been created with the corresponding private key for the
    message to be properly recovered.

    Keyword arguments:
    sig -- A positive integer that resulted from RSA signing.
    pubKey -- A 2-integer list containing the modulus and public exponent of an
              RSA key.
    """
    return rsa_encrypt(sig, pubKey)



if __name__ == "__main__":
    from argparse import ArgumentParser

    random.seed()

    # Setup parser to determine mode of operation
    parser = ArgumentParser(description="""Establish an encrypted connection\
                            between two parties using RSA keys. bob should be\
                            run before alice so that he is available to listen\
                            when she tries to connect. After alice verifies an\
                            encrypted message from bob, the connection is taken\
                            down and alice prints a brief summary.""")
    parser.add_argument('party', choices=['alice', 'bob'],
                        help="""Tell %(prog)s as which party it should\
                        operate. bob listens for a connection. alice initiates\
                        a public key exchange and negotiates a session key with\
                        bob""")
    parser.add_argument('--host', help="""Host name or local interface at\
                                  which bob should listen for a connection. By\
                                  default, bob will listen for a connection\
                                  on """ + DEFAULT_BHOST + """ and alice will\
                                  try to reach bob at """ + DEFAULT_AHOST + '.')
    parser.add_argument('--port', default=DEFAULT_PORT, type=int,
                        help="""TCP port on which bob should listen for a\
                        connection. Must be a valid, open port in the range of\
                        1024-65535. Default is %(default)s.""")
    args = parser.parse_args()

    if args.port < MIN_PORT or args.port > MAX_PORT:
        # Do not accept port out of defined range, even for root
        parser.print_help()
    elif args.party == 'alice':
        # Operate as Alice; Bob must be listening at the provided host and port
        _alice(DEFAULT_AHOST if args.host == None else args.host, args.port)
        print("\nAlice done!")
    else:
        # Operage as Bob; listen for Alice on the provided interface and port
        _bob(DEFAULT_BHOST if args.host == None else args.host, args.port)
        print("\nBob done!")

