
from cryptography.hazmat.primitives.asymmetric import rsa
import time

for i in range(1, 4):
    start = time.perf_counter()

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    end = time.perf_counter()
    print(f"Try (2048) {i}: {end - start:.4f} c")


for i in range(1, 4):
    start = time.perf_counter()

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096
    )

    end = time.perf_counter()
    print(f"Try (4096) {i}: {end - start:.4f} c")
