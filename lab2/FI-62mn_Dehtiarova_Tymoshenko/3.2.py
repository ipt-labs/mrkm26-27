from cryptography.hazmat.primitives.ciphers.aead import AESGCM

key1 = AESGCM.generate_key(bit_length=256)
key2 = AESGCM.generate_key(bit_length=256)

print("Key 1 (hex):", key1.hex())
print("Key 2 (hex):", key2.hex())