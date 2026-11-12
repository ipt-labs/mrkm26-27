"""Лабораторна 3: Ed25519, X25519, HKDF та AES-GCM.
Запуск: python lab3.py all
Закриті ключі й спільні секрети не записуються у файли.
"""
import argparse
import hashlib
import hmac
import io
import json
import os
import platform
from contextlib import redirect_stdout
from pathlib import Path

import cryptography
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def environment():
    return {"python": platform.python_version(),
            "cryptography": cryptography.__version__,
            "platform": platform.system(), "architecture": platform.machine()}


def save_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n",
                    encoding="utf-8")


def accepts_signature(public, signature, message):
    try:
        public.verify(signature, message)
        return True
    except InvalidSignature:
        return False


def signature_demo(output):
    private = Ed25519PrivateKey.generate()
    public = private.public_key()
    other_public = Ed25519PrivateKey.generate().public_key()
    message = "Лабораторна 3: підтвердження цілісності документа.".encode("utf-8")
    changed = message + b"!"
    signature = private.sign(message)
    checks = {"original_accepted": accepts_signature(public, signature, message),
              "changed_rejected": not accepts_signature(public, signature, changed),
              "other_key_rejected": not accepts_signature(other_public, signature, message)}
    if not all(checks.values()):
        raise RuntimeError("Неочікуваний результат перевірки підпису")
    # Зберігаються лише публічні дані для незалежної повторної перевірки.
    (output / "message.txt").write_bytes(message)
    (output / "signature.bin").write_bytes(signature)
    (output / "ed25519_public.bin").write_bytes(public.public_bytes_raw())
    result = {"environment": environment(), "algorithm": "Ed25519",
              "message": message.decode("utf-8"), "signature_bytes": len(signature),
              "public_key_hex": public.public_bytes_raw().hex(),
              "other_public_key_hex": other_public.public_bytes_raw().hex(),
              "signature_hex": signature.hex(), "checks": checks}
    save_json(output / "signature_results.json", result)
    print("Ed25519: створення та перевірка підпису")
    print(f"Python {platform.python_version()} | cryptography {cryptography.__version__}")
    print("Повідомлення:", message.decode("utf-8"))
    print("Відкритий ключ:", public.public_bytes_raw().hex())
    print(f"Підпис: {len(signature)} байти")
    print("Оригінал + правильний ключ: ПРИЙНЯТО")
    print("Змінене повідомлення: ВІДХИЛЕНО (InvalidSignature)")
    print("Інший відкритий ключ: ВІДХИЛЕНО (InvalidSignature)")
    print("Очікувані результати: 3/3")
    print("Публічні дані збережено; закритий ключ не експортовано.")


def derive_key(secret, salt, context):
    # Для кожної сторони потрібен новий об'єкт HKDF.
    return HKDF(algorithm=hashes.SHA256(), length=32,
                salt=salt, info=context).derive(secret)


def agreement_demo(output):
    alice = X25519PrivateKey.generate()
    bob = X25519PrivateKey.generate()
    alice_wire = alice.public_key().public_bytes_raw()
    bob_wire = bob.public_key().public_bytes_raw()
    # Симулюємо передачу й десеріалізацію тільки відкритих ключів.
    alice_secret = alice.exchange(X25519PublicKey.from_public_bytes(bob_wire))
    bob_secret = bob.exchange(X25519PublicKey.from_public_bytes(alice_wire))
    shared_equal = hmac.compare_digest(alice_secret, bob_secret)
    salt = os.urandom(32)  # Публічна сіль; не потребує секретності.
    context = b"lab3/x25519/aes256gcm/v1" + alice_wire + bob_wire
    alice_key = derive_key(alice_secret, salt, context)
    bob_key = derive_key(bob_secret, salt, context)
    key_equal = hmac.compare_digest(alice_key, bob_key)
    # Додаткова перевірка практичного використання погодженого ключа.
    nonce = os.urandom(12)
    aad = b"lab3-demo-v1"
    message = b"Alice -> Bob: authenticated encrypted message"
    ciphertext = AESGCM(alice_key).encrypt(nonce, message, aad)
    decrypted = AESGCM(bob_key).decrypt(nonce, ciphertext, aad)
    altered = bytearray(ciphertext)
    altered[0] ^= 1
    try:
        AESGCM(bob_key).decrypt(nonce, bytes(altered), aad)
        tamper_rejected = False
    except InvalidTag:
        tamper_rejected = True
    checks = {"shared_secrets_equal": shared_equal, "derived_keys_equal": key_equal,
              "aead_roundtrip": decrypted == message, "aead_tamper_rejected": tamper_rejected}
    if not all(checks.values()):
        raise RuntimeError("Неочікуваний результат узгодження ключів")
    fingerprints = {"alice": hashlib.sha256(alice_secret).hexdigest(),
                    "bob": hashlib.sha256(bob_secret).hexdigest()}
    result = {"environment": environment(), "algorithm": "X25519 + HKDF-SHA256",
              "alice_public_hex": alice_wire.hex(), "bob_public_hex": bob_wire.hex(),
              "shared_secret_bytes": len(alice_secret), "fingerprints_sha256": fingerprints,
              "derived_key_bytes": len(alice_key), "public_salt_hex": salt.hex(),
              "public_context_hex": context.hex(), "checks": checks,
              "authentication_of_peers": False}
    save_json(output / "agreement_results.json", result)
    print("X25519: узгодження секрету Alice та Bob")
    print(f"Python {platform.python_version()} | cryptography {cryptography.__version__}")
    print("Alice public:", alice_wire.hex())
    print("Bob public:  ", bob_wire.hex())
    print("Між сторонами передано два відкриті ключі по 32 байти.")
    print("Спільний секрет: 32 байти | пряме порівняння: ЗБІГ")
    print("SHA-256 секрету Alice:", fingerprints["alice"])
    print("SHA-256 секрету Bob:  ", fingerprints["bob"])
    print("HKDF-SHA256: ключі по 32 байти | порівняння: ЗБІГ")
    print("AES-256-GCM: розшифрування: OK")
    print("AES-256-GCM: підміна шифротексту: ВІДХИЛЕНО (InvalidTag)")
    print("Секрет і ключ не передавалися та не записувалися у файли.")
    print("Ця модель не автентифікує Alice та Bob: можливий MITM.")
    print("Очікувані результати: 4/4")


def recorded_demo(name, function, output):
    stream = io.StringIO()
    with redirect_stdout(stream):
        function(output)
    transcript = f"ЗАПУСК: python lab3.py {name}\n" + stream.getvalue()
    (output / f"{name}_console.txt").write_text(transcript, encoding="utf-8")
    print(transcript, end="\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("signature", "agreement", "all"))
    parser.add_argument("--output-dir", type=Path, default=Path("results"))
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    if args.command in ("signature", "all"):
        recorded_demo("signature", signature_demo, args.output_dir)
    if args.command in ("agreement", "all"):
        recorded_demo("agreement", agreement_demo, args.output_dir)


if __name__ == "__main__":
    main()
