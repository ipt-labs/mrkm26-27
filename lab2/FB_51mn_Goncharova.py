
import argparse
import json
import os
import platform
import random
import secrets
import statistics
import subprocess
import sys
from pathlib import Path
from time import perf_counter

import cryptography
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def environment():
    return {"python": platform.python_version(),
            "cryptography": cryptography.__version__,
            "os": platform.system(), "architecture": platform.machine()}


def save_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n",
                    encoding="utf-8")


def run_rng(output):
    seed = 2026
    generator = random.Random(seed)
    first = [generator.randrange(1000) for _ in range(8)]
    generator.seed(seed)
    repeated = [generator.randrange(1000) for _ in range(8)]
    if first != repeated:
        raise RuntimeError("PRNG не відтворив послідовність")
    # Відкритий вивід ключів потрібний лише для навчального порівняння.
    keys = [secrets.token_bytes(32) for _ in range(3)]
    if any(len(key) != 32 for key in keys):
        raise RuntimeError("Некоректна довжина ключа")
    save_json(output, {"environment": environment(), "pid": os.getpid(),
        "seed": seed, "prng_first": first, "prng_repeated": repeated,
        "csprng_keys_hex": [key.hex() for key in keys]})
    print(f"PID={os.getpid()} | seed={seed} | Python {platform.python_version()}")
    print("PRNG 1:", first)
    print("PRNG 2:", repeated)
    print("PRNG після повторного seed: збіг")
    print("CSPRNG: 3 навчальні ключі по 32 байти; не використовувати далі")
    for i, key in enumerate(keys, 1):
        print(f"K{i}: {key.hex()}")


def compare_rng(first_path, second_path, output):
    a = json.loads(first_path.read_text(encoding="utf-8"))
    b = json.loads(second_path.read_text(encoding="utf-8"))
    same_prng = a["prng_first"] == b["prng_first"]
    keys_a, keys_b = a["csprng_keys_hex"], b["csprng_keys_hex"]
    common = len(set(keys_a) & set(keys_b))
    unique = len(set(keys_a + keys_b))
    if not same_prng:
        raise RuntimeError("PRNG із тим самим seed відрізняється між процесами")
    print("PRNG між запусками:", "однаковий" if same_prng else "різний")
    print(f"CSPRNG: спільних ключів між запусками {common}; різних загалом {unique}/6")
    print("Різні значення самі по собі не доводять криптостійкість.")
    save_json(output, {"prng_equal": same_prng, "common_keys": common,
        "unique_keys": unique, "pids": [a["pid"], b["pid"]]})


def run_rsa(output, trials):
    result = {"environment": environment(), "trials_per_size": trials,
              "public_exponent": 65537, "rsa": {}}
    print(f"Python {platform.python_version()} | cryptography {cryptography.__version__}")
    print(f"{platform.system()} {platform.machine()} | e=65537 | {trials} повторів")
    print("Час лише generate_private_key; перевірка підпису поза виміром.")
    all_moduli = set()
    message = b"Lab 2: generated RSA key pair check"
    scheme = padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                         salt_length=padding.PSS.DIGEST_LENGTH)
    for bits in (2048, 4096):
        times = []
        print(f"\nRSA-{bits}")
        for i in range(trials):
            start = perf_counter()
            key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
            elapsed = (perf_counter() - start) * 1000
            public = key.public_key()
            modulus = public.public_numbers().n
            if key.key_size != bits or modulus in all_moduli:
                raise RuntimeError("Некоректний або повторний RSA-ключ")
            all_moduli.add(modulus)
            signature = key.sign(message, scheme, hashes.SHA256())
            public.verify(signature, message, scheme, hashes.SHA256())
            times.append(elapsed)
            print(f"  Спроба {i + 1}: {elapsed:8.3f} мс | перевірка пари OK")
        stats = {"times_ms": times, "min_ms": min(times), "max_ms": max(times),
                 "mean_ms": statistics.mean(times), "median_ms": statistics.median(times)}
        result["rsa"][str(bits)] = stats
        print(f"  Середнє: {stats['mean_ms']:.3f} мс; медіана: {stats['median_ms']:.3f} мс")
    ratio = result["rsa"]["4096"]["mean_ms"] / result["rsa"]["2048"]["mean_ms"]
    result["mean_ratio_4096_to_2048"] = ratio
    result["key_pairs_checked"] = 2 * trials
    print(f"\nВідношення середніх RSA-4096/RSA-2048: {ratio:.2f}")
    print(f"Перевірено {2 * trials}/{2 * trials} пар; приватні ключі не збережено.")
    save_json(output, result)


def run_all(output_dir, trials):
    output_dir.mkdir(parents=True, exist_ok=True)
    script = str(Path(__file__).resolve())
    rng_logs = []
    for number in (1, 2):
        destination = output_dir / f"run_{number}.json"
        # Кожний виклик запускає новий незалежний процес Python.
        completed = subprocess.run(
            [sys.executable, script, "rng", "--output", str(destination)],
            check=True, capture_output=True, text=True, encoding="utf-8",
        env={**os.environ, "PYTHONIOENCODING": "utf-8"})
        log = f"ЗАПУСК {number}: python lab2.py rng --output {destination}\n" + completed.stdout
        rng_logs.append(log)
        print(log, end="\n")
    completed = subprocess.run(
        [sys.executable, script, "compare", str(output_dir / "run_1.json"),
         str(output_dir / "run_2.json"), "--output", str(output_dir / "comparison.json")],
        check=True, capture_output=True, text=True, encoding="utf-8",
        env={**os.environ, "PYTHONIOENCODING": "utf-8"})
    rng_logs.append(completed.stdout)
    print(completed.stdout)
    (output_dir / "rng_console.txt").write_text("\n".join(rng_logs), encoding="utf-8")
    completed = subprocess.run(
        [sys.executable, script, "rsa", "--trials", str(trials), "--output",
         str(output_dir / "rsa_results.json")],
        check=True, capture_output=True, text=True, encoding="utf-8",
        env={**os.environ, "PYTHONIOENCODING": "utf-8"})
    log = f"ЗАПУСК: python lab2.py rsa --trials {trials}\n" + completed.stdout
    print(log)
    (output_dir / "rsa_console.txt").write_text(log, encoding="utf-8")


def positive_integer(value):
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("Кількість повторів має бути додатною")
    return number


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    rng = commands.add_parser("rng", help="PRNG і 3 CSPRNG-ключі")
    rng.add_argument("--output", type=Path, default=Path("results/run.json"))
    compare = commands.add_parser("compare", help="Порівняти два запуски")
    compare.add_argument("first", type=Path)
    compare.add_argument("second", type=Path)
    compare.add_argument("--output", type=Path, default=Path("results/comparison.json"))
    asym = commands.add_parser("rsa", help="Генерація RSA-2048 і RSA-4096")
    asym.add_argument("--trials", type=positive_integer, default=5)
    asym.add_argument("--output", type=Path, default=Path("results/rsa_results.json"))
    all_cmd = commands.add_parser("all", help="Усі досліди в окремих процесах")
    all_cmd.add_argument("--trials", type=positive_integer, default=5)
    all_cmd.add_argument("--output-dir", type=Path, default=Path("results"))
    args = parser.parse_args()
    if args.command == "rng":
        run_rng(args.output)
    elif args.command == "compare":
        compare_rng(args.first, args.second, args.output)
    elif args.command == "rsa":
        run_rsa(args.output, args.trials)
    else:
        run_all(args.output_dir, args.trials)


if __name__ == "__main__":
    main()
