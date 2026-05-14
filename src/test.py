"""
main.py

Điểm chạy chính của project RSA Common Modulus Attack Demo.

Chạy từ thư mục gốc project bằng:

    python -m src.main demo
    python -m src.main demo --message "HELLO PTIT" --bits 512

    python -m src.main demo-pp1 --message "HELLO" --bits 512
    python -m src.main demo-pp2 --message "HELLO" --bits 512

    python -m src.main attack-pp1 --n 253 --victim-e 13 --attacker-e 23 --attacker-d 67 --ciphertext 27
    python -m src.main attack-pp2 --n 247 --e1 5 --e2 7 --c1 140 --c2 30

Lưu ý:
- Đây là textbook RSA phục vụ học tập.
- Không dùng chương trình này cho bảo mật thực tế.
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any

from rich.panel import Panel

from .common_modulus_attack import common_modulus_attack_pp1
from .common_modulus_attack import common_modulus_attack_pp2
from .display import (
    console,
    print_attack_trace,
    print_encryption_info,
    print_final_result,
    print_keys_info,
    print_manual_attack_result,
    print_message_info,
    print_modulus_info,
    print_pp1_encryption_info,
    print_timing_info,
    print_title,
)
from .file_codec import (
    bytes_to_int,
    ensure_message_fits_modulus,
    int_to_bytes,
    int_to_text,
    read_file_as_bytes,
    text_to_int,
    write_bytes_to_file,
)
from .rsa_core import (
    generate_two_keys_with_shared_n,
    rsa_encrypt_int,
)

DEFAULT_MESSAGE = "HELLO PTIT - COMMON MODULUS ATTACK DEMO"


def parse_int(value: str) -> int:
    """
    Chuyển chuỗi CLI thành số nguyên.

    Hỗ trợ:
        247
        0xf7
        0b11110111
    """
    try:
        return int(value, 0)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            f"Không chuyển được '{value}' thành số nguyên."
        ) from exc


def load_demo_message(args: argparse.Namespace) -> tuple[str, bytes, int]:
    """
    Lấy message từ --message hoặc --file.

    Returns:
        tuple:
            (
                message_display,
                message_bytes,
                message_int
            )
    """
    if args.file is not None:
        file_path = Path(args.file)
        message_bytes = read_file_as_bytes(file_path)
        message_int = bytes_to_int(message_bytes)

        try:
            decoded_text = message_bytes.decode("utf-8")
            message_display = decoded_text
        except UnicodeDecodeError:
            message_display = (
                f"<file: {file_path}, {len(message_bytes)} bytes, "
                "không hiển thị được dạng UTF-8>"
            )

        return message_display, message_bytes, message_int

    message_text = args.message
    message_bytes = message_text.encode("utf-8")
    message_int = text_to_int(message_text)

    return message_text, message_bytes, message_int


def recover_text_safely(value: int) -> str | None:
    """
    Thử chuyển số nguyên khôi phục về text UTF-8.

    Nếu không giải mã được thì trả về None.
    """
    try:
        text = int_to_text(value)
    except UnicodeDecodeError:
        return None

    return text


def save_demo_json(
    output_path: str | None,
    data: dict[str, Any],
) -> None:
    """
    Lưu dữ liệu demo ra JSON nếu người dùng truyền --save-json.
    """
    if output_path is None:
        return

    path = Path(output_path)

    if path.parent != Path("."):
        path.parent.mkdir(parents=True, exist_ok=True)

    json_text = json.dumps(data, indent=4, ensure_ascii=False)
    path.write_text(json_text, encoding="utf-8")

    console.print(f"[green]✓ Đã lưu dữ liệu demo vào:[/green] {path}")


def write_recovered_output_file(
    output_file: str | None,
    recovered_m: int,
    length: int | None = None,
) -> None:
    """
    Ghi recovered_m ra file nếu người dùng truyền output_file.
    """
    if output_file is None:
        return

    recovered_bytes = int_to_bytes(recovered_m, length=length)
    write_bytes_to_file(recovered_bytes, output_file)

    console.print(f"[green]✓ Đã ghi dữ liệu khôi phục ra:[/green] {output_file}")


def run_demo_pp2(args: argparse.Namespace) -> None:
    """
    Chạy demo tự động PP2:

    1. Nhận message.
    2. Sinh n dùng chung.
    3. Tạo hai public key khác e.
    4. Mã hóa cùng một message thành C1, C2.
    5. Dùng PP2 khôi phục message.
    6. In toàn bộ trace.
    """
    timings: dict[str, float] = {}
    total_start = time.perf_counter()

    print_title("DEMO TỰ ĐỘNG PP2: KHÔI PHỤC BẢN RÕ TỪ C1, C2")

    message_display, message_bytes, message_int = load_demo_message(args)

    start = time.perf_counter()
    key_bundle = generate_two_keys_with_shared_n(args.bits)
    timings["Sinh modulus và hai cặp khóa"] = time.perf_counter() - start

    modulus_info = key_bundle["modulus_info"]
    key1 = key_bundle["key1"]
    key2 = key_bundle["key2"]

    n = modulus_info["n"]
    e1 = key1["e"]
    e2 = key2["e"]

    try:
        ensure_message_fits_modulus(message_int, n)
    except ValueError as exc:
        message_bits = message_int.bit_length()
        n_bits = n.bit_length()

        raise ValueError(
            "Message hiện tại quá lớn so với modulus n.\n"
            f"- message_int có khoảng {message_bits} bit\n"
            f"- n có khoảng {n_bits} bit\n"
            "Cách sửa: tăng --bits hoặc dùng message ngắn hơn.\n"
            'Ví dụ: python -m src.main demo-pp2 --message "HELLO" --bits 512'
        ) from exc

    start = time.perf_counter()
    c1 = rsa_encrypt_int(message_int, e1, n)
    c2 = rsa_encrypt_int(message_int, e2, n)
    timings["Mã hóa C1, C2"] = time.perf_counter() - start

    start = time.perf_counter()
    recovered_m, trace = common_modulus_attack_pp2(
        c1=c1,
        c2=c2,
        e1=e1,
        e2=e2,
        n=n,
    )
    timings["Common Modulus Attack PP2"] = time.perf_counter() - start

    recovered_text = recover_text_safely(recovered_m)

    if args.output_file is not None:
        write_recovered_output_file(
            output_file=args.output_file,
            recovered_m=recovered_m,
            length=len(message_bytes),
        )

    print_modulus_info(modulus_info)
    print_keys_info(key1, key2, key1_label="victim/key1", key2_label="receiver/key2")
    print_message_info(message_display, message_int)
    print_encryption_info(message_int, c1, c2, e1, e2, n)
    print_attack_trace(trace)
    print_final_result(message_int, recovered_m, recovered_text)

    timings["Tổng thời gian"] = time.perf_counter() - total_start
    print_timing_info(timings)

    demo_json = {
        "mode": "demo-pp2",
        "bits": args.bits,
        "message_display": message_display,
        "message_int": message_int,
        "message_length_bytes": len(message_bytes),
        "modulus_info": modulus_info,
        "key1": key1,
        "key2": key2,
        "attack_public_data": {
            "n": n,
            "e1": e1,
            "e2": e2,
            "c1": c1,
            "c2": c2,
        },
        "recovered_m": recovered_m,
        "recovered_text": recovered_text,
        "success": message_int == recovered_m,
        "timings": timings,
    }

    save_demo_json(args.save_json, demo_json)


def run_demo_pp1(args: argparse.Namespace) -> None:
    """
    Chạy demo tự động PP1:

    1. Nhận message.
    2. Sinh n dùng chung.
    3. Tạo victim key và attacker key dùng chung n.
    4. Mã hóa message bằng public key của victim.
    5. Attacker dùng e_attacker, d_attacker, victim_e để tìm victim_d.
    6. Giải mã ciphertext.
    """
    timings: dict[str, float] = {}
    total_start = time.perf_counter()

    print_title("DEMO TỰ ĐỘNG PP1: KHÔI PHỤC KHÓA BÍ MẬT VICTIM")

    message_display, message_bytes, message_int = load_demo_message(args)

    start = time.perf_counter()
    key_bundle = generate_two_keys_with_shared_n(args.bits)
    timings["Sinh modulus và hai cặp khóa"] = time.perf_counter() - start

    modulus_info = key_bundle["modulus_info"]
    victim_key = key_bundle["key1"]
    attacker_key = key_bundle["key2"]

    n = modulus_info["n"]
    victim_e = victim_key["e"]
    attacker_e = attacker_key["e"]
    attacker_d = attacker_key["d"]

    try:
        ensure_message_fits_modulus(message_int, n)
    except ValueError as exc:
        message_bits = message_int.bit_length()
        n_bits = n.bit_length()

        raise ValueError(
            "Message hiện tại quá lớn so với modulus n.\n"
            f"- message_int có khoảng {message_bits} bit\n"
            f"- n có khoảng {n_bits} bit\n"
            "Cách sửa: tăng --bits hoặc dùng message ngắn hơn.\n"
            'Ví dụ: python -m src.main demo-pp1 --message "HELLO" --bits 512'
        ) from exc

    start = time.perf_counter()
    ciphertext = rsa_encrypt_int(message_int, victim_e, n)
    timings["Mã hóa bằng public key của victim"] = time.perf_counter() - start

    start = time.perf_counter()
    recovered_victim_d, recovered_m, trace = common_modulus_attack_pp1(
        ciphertext=ciphertext,
        victim_e=victim_e,
        attacker_e=attacker_e,
        attacker_d=attacker_d,
        n=n,
    )
    timings["Common Modulus Attack PP1"] = time.perf_counter() - start

    recovered_text = recover_text_safely(recovered_m)

    if args.output_file is not None:
        write_recovered_output_file(
            output_file=args.output_file,
            recovered_m=recovered_m,
            length=len(message_bytes),
        )

    print_modulus_info(modulus_info)
    print_keys_info(
        victim_key,
        attacker_key,
        key1_label="victim",
        key2_label="attacker",
    )
    print_message_info(message_display, message_int)
    print_pp1_encryption_info(message_int, ciphertext, victim_e, n)
    print_attack_trace(trace)
    print_final_result(message_int, recovered_m, recovered_text)

    timings["Tổng thời gian"] = time.perf_counter() - total_start
    print_timing_info(timings)

    demo_json = {
        "mode": "demo-pp1",
        "bits": args.bits,
        "message_display": message_display,
        "message_int": message_int,
        "message_length_bytes": len(message_bytes),
        "modulus_info": modulus_info,
        "victim_key": victim_key,
        "attacker_key": attacker_key,
        "attack_public_data": {
            "n": n,
            "ciphertext": ciphertext,
            "victim_e": victim_e,
            "attacker_e": attacker_e,
            "attacker_d": attacker_d,
        },
        "recovered_victim_d": recovered_victim_d,
        "recovered_m": recovered_m,
        "recovered_text": recovered_text,
        "success": message_int == recovered_m,
        "timings": timings,
    }

    save_demo_json(args.save_json, demo_json)


def run_attack_pp2(args: argparse.Namespace) -> None:
    """
    Chạy attack thủ công PP2.

    Người dùng nhập:
        n, e1, e2, c1, c2
    """
    timings: dict[str, float] = {}

    print_title("ATTACK THỦ CÔNG PP2: KHÔI PHỤC BẢN RÕ TỪ C1, C2")

    start = time.perf_counter()
    recovered_m, trace = common_modulus_attack_pp2(
        c1=args.c1,
        c2=args.c2,
        e1=args.e1,
        e2=args.e2,
        n=args.n,
    )
    timings["Common Modulus Attack PP2"] = time.perf_counter() - start

    recovered_text: str | None = None

    if args.decode_text:
        recovered_text = recover_text_safely(recovered_m)

    if args.output_file is not None:
        write_recovered_output_file(
            output_file=args.output_file,
            recovered_m=recovered_m,
            length=args.output_length,
        )

    print_attack_trace(trace)
    print_manual_attack_result(
        recovered_m=recovered_m,
        recovered_text=recovered_text,
        output_file=args.output_file,
    )
    print_timing_info(timings)


def run_attack_pp1(args: argparse.Namespace) -> None:
    """
    Chạy attack thủ công PP1.

    Người dùng nhập:
        n, ciphertext, victim_e, attacker_e, attacker_d
    """
    timings: dict[str, float] = {}

    print_title("ATTACK THỦ CÔNG PP1: KHÔI PHỤC PRIVATE EXPONENT CỦA VICTIM")

    start = time.perf_counter()
    recovered_victim_d, recovered_m, trace = common_modulus_attack_pp1(
        ciphertext=args.ciphertext,
        victim_e=args.victim_e,
        attacker_e=args.attacker_e,
        attacker_d=args.attacker_d,
        n=args.n,
    )
    timings["Common Modulus Attack PP1"] = time.perf_counter() - start

    recovered_text: str | None = None

    if args.decode_text:
        recovered_text = recover_text_safely(recovered_m)

    if args.output_file is not None:
        write_recovered_output_file(
            output_file=args.output_file,
            recovered_m=recovered_m,
            length=args.output_length,
        )

    print_attack_trace(trace)
    print_manual_attack_result(
        recovered_m=recovered_m,
        recovered_text=recovered_text,
        recovered_d=recovered_victim_d,
        output_file=args.output_file,
    )
    print_timing_info(timings)


def add_demo_arguments(parser: argparse.ArgumentParser) -> None:
    """
    Thêm argument chung cho demo-pp1 và demo-pp2.
    """
    message_group = parser.add_mutually_exclusive_group()

    message_group.add_argument(
        "--message",
        type=str,
        default=DEFAULT_MESSAGE,
        help=f"Message text để demo. Mặc định: {DEFAULT_MESSAGE!r}",
    )

    message_group.add_argument(
        "--file",
        type=str,
        default=None,
        help="Đường dẫn file đầu vào để demo. Lưu ý file phải đủ nhỏ để m < n.",
    )

    parser.add_argument(
        "--bits",
        type=int,
        default=512,
        help="Độ dài mong muốn của modulus n. Mặc định: 512.",
    )

    parser.add_argument(
        "--save-json",
        type=str,
        default=None,
        help="Nếu truyền, chương trình sẽ lưu bộ dữ liệu demo ra JSON.",
    )

    parser.add_argument(
        "--output-file",
        type=str,
        default=None,
        help="Nếu truyền, ghi dữ liệu khôi phục ra file.",
    )


def add_output_arguments(parser: argparse.ArgumentParser) -> None:
    """
    Thêm argument output chung cho attack thủ công.
    """
    parser.add_argument(
        "--decode-text",
        action="store_true",
        help="Thử decode recovered M về text UTF-8.",
    )

    parser.add_argument(
        "--output-file",
        type=str,
        default=None,
        help="Nếu truyền, ghi recovered M ra file dạng bytes.",
    )

    parser.add_argument(
        "--output-length",
        type=int,
        default=None,
        help="Số byte khi ghi output-file. Hữu ích nếu dữ liệu gốc có byte 0 ở đầu.",
    )


def add_attack_pp2_arguments(parser: argparse.ArgumentParser) -> None:
    """
    Thêm argument cho attack PP2.
    """
    parser.add_argument(
        "--n",
        type=parse_int,
        required=True,
        help="Modulus RSA dùng chung.",
    )

    parser.add_argument(
        "--e1",
        type=parse_int,
        required=True,
        help="Public exponent thứ nhất.",
    )

    parser.add_argument(
        "--e2",
        type=parse_int,
        required=True,
        help="Public exponent thứ hai.",
    )

    parser.add_argument(
        "--c1",
        type=parse_int,
        required=True,
        help="Ciphertext thứ nhất.",
    )

    parser.add_argument(
        "--c2",
        type=parse_int,
        required=True,
        help="Ciphertext thứ hai.",
    )

    add_output_arguments(parser)


def add_attack_pp1_arguments(parser: argparse.ArgumentParser) -> None:
    """
    Thêm argument cho attack PP1.
    """
    parser.add_argument(
        "--n",
        type=parse_int,
        required=True,
        help="Modulus RSA dùng chung.",
    )

    parser.add_argument(
        "--ciphertext",
        type=parse_int,
        required=True,
        help="Ciphertext cần giải.",
    )

    parser.add_argument(
        "--victim-e",
        dest="victim_e",
        type=parse_int,
        required=True,
        help="Public exponent của victim.",
    )

    parser.add_argument(
        "--attacker-e",
        dest="attacker_e",
        type=parse_int,
        required=True,
        help="Public exponent của attacker.",
    )

    parser.add_argument(
        "--attacker-d",
        dest="attacker_d",
        type=parse_int,
        required=True,
        help="Private exponent của attacker.",
    )

    add_output_arguments(parser)


def build_parser() -> argparse.ArgumentParser:
    """
    Tạo CLI parser cho chương trình.
    """
    parser = argparse.ArgumentParser(
        prog="python -m src.main",
        description="RSA Common Modulus Attack Demo CLI",
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    demo_parser = subparsers.add_parser(
        "demo",
        help="Alias của demo-pp2. Chạy demo PP2 tự động.",
    )
    add_demo_arguments(demo_parser)
    demo_parser.set_defaults(func=run_demo_pp2)

    demo_pp2_parser = subparsers.add_parser(
        "demo-pp2",
        help="Chạy demo PP2: dùng C1, C2, e1, e2 để khôi phục bản rõ.",
    )
    add_demo_arguments(demo_pp2_parser)
    demo_pp2_parser.set_defaults(func=run_demo_pp2)

    demo_pp1_parser = subparsers.add_parser(
        "demo-pp1",
        help="Chạy demo PP1: dùng khóa attacker để tìm private exponent của victim.",
    )
    add_demo_arguments(demo_pp1_parser)
    demo_pp1_parser.set_defaults(func=run_demo_pp1)

    attack_parser = subparsers.add_parser(
        "attack",
        help="Alias của attack-pp2. Chạy attack PP2 thủ công.",
    )
    add_attack_pp2_arguments(attack_parser)
    attack_parser.set_defaults(func=run_attack_pp2)

    attack_pp2_parser = subparsers.add_parser(
        "attack-pp2",
        help="Chạy attack PP2 thủ công với n, e1, e2, c1, c2.",
    )
    add_attack_pp2_arguments(attack_pp2_parser)
    attack_pp2_parser.set_defaults(func=run_attack_pp2)

    attack_pp1_parser = subparsers.add_parser(
        "attack-pp1",
        help="Chạy attack PP1 thủ công với n, victim_e, attacker_e, attacker_d, ciphertext.",
    )
    add_attack_pp1_arguments(attack_pp1_parser)
    attack_pp1_parser.set_defaults(func=run_attack_pp1)

    return parser


def main() -> None:
    """
    Entry point chính.
    """
    parser = build_parser()
    args = parser.parse_args()

    try:
        args.func(args)
    except Exception as exc:
        console.print()
        console.print(
            Panel(
                str(exc),
                title="Lỗi",
                border_style="red",
            )
        )
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
