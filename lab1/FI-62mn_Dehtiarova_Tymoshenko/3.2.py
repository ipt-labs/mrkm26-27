from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

#1
private_key = ed25519.Ed25519PrivateKey.generate()
public_key = private_key.public_key()

pub_bytes = public_key.public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw
)

message = b"Hello, my name is Mariia"

print("Private key: generated (held in memory, not exported)")
print("Public key (raw hex):", pub_bytes.hex())
print("Original message:", message)

#2
signature = private_key.sign(message)

print("\nSignature (hex):", signature.hex())
print("Signature length:", len(signature), "bytes")

#3
try:
    public_key.verify(signature, message)
    print("Verification result: Signature is VALID")
except InvalidSignature:
    print("Verification result: Signature is INVALID")


#4
modified_message = b"Hello, my name is Mariia!"

print("\nModified message:", modified_message)

try:
    public_key.verify(signature, modified_message)
    print("Verification result: Signature is VALID")
except InvalidSignature:
    print("Verification result: Signature verification FAILED (InvalidSignature)")
