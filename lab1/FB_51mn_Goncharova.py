"""Лабораторна робота 1, варіант А. Python + cryptography.
Запуск: python lab1.py --output-dir results
Секретні ключі створюються заново і не записуються до файлів.
"""
import argparse
import html
import json
import platform
from pathlib import Path
from secrets import token_bytes

import cryptography
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def demo_aead():
    message = b"Confidential user data: user_id=42"
    aad = b"lab1|record=42|version=1"
    key = AESGCM.generate_key(bit_length=256)
    # Один новий ключ на запуск; під цим ключем шифрується одне повідомлення.
    nonce = token_bytes(12)
    aes = AESGCM(key)
    encrypted = aes.encrypt(nonce, message, aad)
    restored = aes.decrypt(nonce, encrypted, aad)
    require(restored == message, "Помилка відновлення повідомлення")
    modified = bytearray(encrypted)
    modified[0] ^= 1  # Один байт шифротексту; tag не змінюється.
    rejected = False
    try:
        aes.decrypt(nonce, bytes(modified), aad)
    except InvalidTag:
        rejected = True
    require(rejected, "Пошкоджений шифротекст було прийнято")
    lines = [
        "Алгоритм: AES-256-GCM",
        f"Повідомлення: {message.decode()}",
        f"Ключ: {len(key) * 8} біт (значення не виводиться)",
        f"Nonce ({len(nonce)} байт): {nonce.hex()}",
        f"AAD: {aad.decode()}",
        f"Шифротекст ({len(encrypted)-16} байт):",
        encrypted[:-16].hex(),
        f"Tag (16 байт): {encrypted[-16:].hex()}",
        f"Відновлено: {restored.decode()}",
        "Початкові дані: PASS",
        f"Зміна байта 0: {encrypted[0]:02x} -> {modified[0]:02x}",
        "Змінений шифротекст: InvalidTag — відхилено, PASS",
    ]
    return lines


def demo_signature():
    message = b"Approve document 42"
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    signature = private_key.sign(message)
    public_key.verify(signature, message)  # Успіх: немає винятку.
    modified = b"Approve document 43"
    rejected = False
    try:
        public_key.verify(signature, modified)
    except InvalidSignature:
        rejected = True
    require(rejected, "Підпис зміненого повідомлення було прийнято")
    public_bytes = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    lines = [
        "Алгоритм: Ed25519",
        f"Повідомлення: {message.decode()}",
        "Закритий ключ: створено, не експортується",
        f"Відкритий ключ ({len(public_bytes)} байт):",
        public_bytes.hex(),
        f"Підпис ({len(signature)} байт), hex у двох рядках:",
        signature.hex()[:64],
        signature.hex()[64:],
        "Перевірка початкового повідомлення: PASS",
        f"Змінене повідомлення: {modified.decode()}",
        "Повторна перевірка: InvalidSignature — відхилено, PASS",
    ]
    return lines


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=Path("results"))
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    environment = f"Python {platform.python_version()} | cryptography {cryptography.__version__}"
    sections = [("aead", "Автентифіковане шифрування", demo_aead()),
                ("signature", "Цифровий підпис", demo_signature())]
    result = {"environment": environment, "checks_passed": 4}
    for name, title, lines in sections:
        text = "\n".join([environment, *lines])
        print(text + "\n")
        result[name] = lines
        (args.output_dir / f"{name}.txt").write_text(text + "\n", encoding="utf-8")
        page = ("<!doctype html><html lang='uk'><meta charset='utf-8'>"
                "<title>Лабораторна робота 1</title><style>"
                "body{margin:0;padding:28px;background:white;color:#111;}"
                "h1{font:26px 'Times New Roman';margin:0 0 16px;}"
                "pre{font:20px/1.55 'Times New Roman';white-space:pre-wrap;margin:0;}"
                "</style><h1>" + html.escape(title) + "</h1><pre>"
                + html.escape(text) + "</pre></html>")
        (args.output_dir / f"{name}.html").write_text(page, encoding="utf-8")
    (args.output_dir / "results.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print("Підсумок: 4/4 контрольні перевірки пройдено.")


if __name__ == "__main__":
    main()
