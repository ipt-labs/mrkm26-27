"""Лабораторна 4: HMAC, пам'ять та програмна модель ротації KEK.
Запуск: python lab4.py all
LocalKMS — навчальна модель в одному процесі, без апаратної ізоляції.
"""
import argparse
import base64
import hashlib
import hmac
import io
import json
import os
import platform
from contextlib import redirect_stdout
from copy import deepcopy
from pathlib import Path

import cryptography
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encode(value):
    return base64.b64encode(value).decode("ascii")


def decode(value):
    return base64.b64decode(value, validate=True)


def save_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def safe_mac_equal(received, expected):
    # Для HMAC-SHA256 довжина MAC публічна й фіксована: 32 байти.
    return len(received) == len(expected) and hmac.compare_digest(received, expected)


def unsafe_count(received, expected):
    """Фрагмент із методички з лічильником; лише для навчального порівняння.
    Це НЕ перевірка MAC для використання в застосунку.
    """
    count = 0
    for i in range(len(expected)):
        count += 1
        if received[i] != expected[i]:
            return False, count
    return True, count


def comparison_demo(output):
    key = os.urandom(32)
    expected = hmac.digest(key, b"lab4 authenticated message", "sha256")
    changed = bytearray(expected)
    changed[0] ^= 1
    positions, counts = [0, 15, 31], []
    for position in positions:
        received = bytearray(expected)
        received[position] ^= 1
        _, count = unsafe_count(received, expected)
        counts.append(count)
    extended = expected + b"!"
    checks = {
        "valid_mac_accepted": safe_mac_equal(expected, expected),
        "changed_mac_rejected": not safe_mac_equal(bytes(changed), expected),
        "short_mac_rejected": not safe_mac_equal(expected[:-1], expected),
        "long_mac_rejected": not safe_mac_equal(extended, expected),
        "prefix_loop_problem_reproduced": unsafe_count(extended, expected)[0]
    }
    if not all(checks.values()):
        raise RuntimeError("Неочікуваний результат порівняння MAC")
    save_json(output / "comparison_results.json",
              {"algorithm": "HMAC-SHA256", "checks": checks,
               "first_difference_positions": positions, "unsafe_comparisons": counts})
    print("HMAC-SHA256: MAC має 32 байти")
    print("compare_digest: правильний MAC: ПРИЙНЯТО")
    print("Змінений / короткий / подовжений MAC: ВІДХИЛЕНО")
    print("Наївний цикл: позиції першої відмінності 0, 15, 31")
    print("Наївний цикл: кількість порівнянь", counts)
    print("Фрагмент без перевірки довжини помилково прийняв MAC + 1 байт.")
    print("Це підрахунок кроків, а не вимірювання часу чи timing attack.")
    print("Очікувані результати: 5/5")


def memory_demo(output):
    # Штучний буфер для демонстрації копій, а не робочий криптографічний ключ.
    buffer = bytearray(os.urandom(32))
    buffer[0] = 0xA5
    independent_copy = bytes(buffer)
    view = memoryview(buffer)
    for i in range(len(buffer)):
        buffer[i] = 0
    checks = {"original_buffer_zeroed": not any(view),
              "independent_copy_survives": independent_copy[0] == 0xA5}
    if not all(checks.values()):
        raise RuntimeError("Неочікуваний результат роботи з буфером")
    save_json(output / "memory_results.json", {"buffer_bytes": 32, "checks": checks,
               "guaranteed_process_wide_erasure": False})
    print("Пам'ять: навчальний bytearray має 32 байти")
    print("Початковий буфер після перезапису: НУЛІ")
    print("Незалежна bytes-копія зберегла початкові дані: ТАК")
    print("Очищення всіх копій у процесі Python цим не гарантовано.")
    print("Очікувані результати: 2/2")


class LocalKMS:
    """Програмна модель KEK; не HSM, не справжній KMS і не межа безпеки.
    Усі KEK доступні процесу Python. Реальної автентифікації клієнта немає.
    """
    def __init__(self):
        self.keys = {}
        self.disabled = set()

    def create(self, version):
        if version in self.keys:
            raise ValueError("Версія вже існує")
        self.keys[version] = AESGCM.generate_key(bit_length=256)

    def active_key(self, version):
        if version in self.disabled:
            raise PermissionError("Версію KEK вимкнено")
        return self.keys[version]

    def wrap(self, version, dek, context):
        nonce = os.urandom(12)
        aad = b"lab4-wrap-v1:" + version.encode("ascii") + b":" + context
        wrapped = AESGCM(self.active_key(version)).encrypt(nonce, dek, aad)
        return {"kek_version": version, "nonce": encode(nonce), "wrapped_dek": encode(wrapped)}

    def unwrap(self, envelope, context):
        version = envelope["kek_version"]
        aad = b"lab4-wrap-v1:" + version.encode("ascii") + b":" + context
        return AESGCM(self.active_key(version)).decrypt(
            decode(envelope["nonce"]), decode(envelope["wrapped_dek"]), aad)

    def disable(self, version):
        if version not in self.keys:
            raise KeyError(version)
        self.disabled.add(version)


def rejected_by(exception, operation):
    try:
        operation()
    except exception:
        return True
    return False


def rotation_demo(output):
    kms = LocalKMS()
    kms.create("kek-v1")
    dek = AESGCM.generate_key(bit_length=256)
    context = b"record:demo-001"
    nonce = os.urandom(12)
    message = b"Confidential laboratory record"
    ciphertext = AESGCM(dek).encrypt(nonce, message, context)
    old_envelope = kms.wrap("kek-v1", dek, context)
    restored_v1 = AESGCM(kms.unwrap(old_envelope, context)).decrypt(nonce, ciphertext, context)
    original_digest = hashlib.sha256(ciphertext).hexdigest()
    kms.create("kek-v2")
    # Планова ротація KEK: повторно захищається DEK, а не весь запис.
    new_envelope = kms.wrap("kek-v2", kms.unwrap(old_envelope, context), context)
    kms.disable("kek-v1")
    restored_v2 = AESGCM(kms.unwrap(new_envelope, context)).decrypt(nonce, ciphertext, context)
    bad_ciphertext = bytearray(ciphertext)
    bad_ciphertext[0] ^= 1
    bad_envelope = deepcopy(new_envelope)
    bad_wrapped = bytearray(decode(bad_envelope["wrapped_dek"]))
    bad_wrapped[0] ^= 1
    bad_envelope["wrapped_dek"] = encode(bytes(bad_wrapped))
    checks = {
        "decrypt_v1": restored_v1 == message,
        "decrypt_v2_after_v1_disabled": restored_v2 == message,
        "data_ciphertext_unchanged": hashlib.sha256(ciphertext).hexdigest() == original_digest,
        "disabled_version_rejected": rejected_by(PermissionError, lambda: kms.unwrap(old_envelope, context)),
        "tampered_ciphertext_rejected": rejected_by(InvalidTag, lambda: AESGCM(dek).decrypt(nonce, bytes(bad_ciphertext), context)),
        "wrong_context_rejected": rejected_by(InvalidTag, lambda: kms.unwrap(new_envelope, b"record:other")),
        "tampered_wrapped_dek_rejected": rejected_by(InvalidTag, lambda: kms.unwrap(bad_envelope, context))
    }
    if not all(checks.values()):
        raise RuntimeError("Неочікуваний результат ротації")
    common = {"record_id": context.decode(), "data_nonce": encode(nonce),
              "ciphertext": encode(ciphertext), "aad": encode(context)}
    save_json(output / "record_v1.json", {**common, "envelope": old_envelope})
    save_json(output / "record_v2.json", {**common, "envelope": new_envelope})
    save_json(output / "rotation_results.json", {"checks": checks,
              "ciphertext_sha256": original_digest, "raw_keys_saved": False,
              "hardware_isolation": False, "dek_changed": False})
    print("Envelope encryption: AES-256-GCM для даних і захисту DEK")
    print("LocalKMS: модель в одному процесі, БЕЗ апаратної ізоляції")
    print("Версії KEK: kek-v1 -> kek-v2; DEK лишився тим самим")
    print("Розшифрування до ротації: OK")
    print("Розшифрування після ротації та вимкнення v1: OK")
    print("Шифротекст даних після зміни обгортки: БЕЗ ЗМІН")
    print("Стара вимкнена версія: ВІДХИЛЕНО (PermissionError)")
    print("Підміна даних / контексту / обгортки: ВІДХИЛЕНО (InvalidTag)")
    print("Сирі DEK і KEK не записано у файли та не виведено.")
    print("При витоку DEK потрібен новий DEK і перешифрування даних.")
    print("Очікувані результати: 7/7")


def recorded(name, function, output):
    stream = io.StringIO()
    with redirect_stdout(stream):
        function(output)
    transcript = f"ЗАПУСК: python lab4.py {name}\n" + stream.getvalue()
    (output / f"{name}_console.txt").write_text(transcript, encoding="utf-8")
    print(transcript, end="\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("comparison", "memory", "rotation", "all"))
    parser.add_argument("--output-dir", type=Path, default=Path("results"))
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    save_json(args.output_dir / "environment.json", {"python": platform.python_version(),
              "cryptography": cryptography.__version__, "os": platform.system(), "arch": platform.machine()})
    for name, function in (("comparison", comparison_demo), ("memory", memory_demo), ("rotation", rotation_demo)):
        if args.command in (name, "all"):
            recorded(name, function, args.output_dir)


if __name__ == "__main__":
    main()
