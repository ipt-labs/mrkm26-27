import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

# 1
key = AESGCM.generate_key(bit_length=256)
aesgcm = AESGCM(key)

message = b"Hello, my name is Mariia"

# 2
nonce = os.urandom(12)
ciphertext = aesgcm.encrypt(nonce, message, None)

print("Message:", message)
print("Key:", key.hex())
print("Nonce:", nonce.hex())
print("Ciphertext:", ciphertext.hex())

# 3
decrypted = aesgcm.decrypt(nonce, ciphertext, None)

print("\nDecrypted message:", decrypted)

# 4
modified_ciphertext = bytearray(ciphertext)
modified_ciphertext[0] ^= 1
modified_ciphertext = bytes(modified_ciphertext)

print("\nModified ciphertext:", modified_ciphertext.hex())

# Try
try:
    aesgcm.decrypt(nonce, modified_ciphertext, None)
    print("Decryption successful")
except InvalidTag:
    print("Error: authentication tag verification failed")