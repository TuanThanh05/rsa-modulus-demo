"""
main.py

Điểm chạy chính của project RSA Common Modulus Attack Demo.

Chạy từ thư mục gốc project bằng:

    python -m src.main demo
    python -m src.main demo --message "HELLO PTIT" --bits 256
    python -m src.main attack --n 247 --e1 5 --e2 7 --c1 140 --c2 30

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
from rich.table import Table
from .common_modulus_attack import common_modulus_attack_pp1
from .common_modulus_attack import common_modulus_attack_pp2
from .display import (
    console,
    format_int,
    print_attack_trace,
    print_encryption_info,
    print_final_result,
    print_keys_info,
    print_message_info,
    print_modulus_info,
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
        message_bytes = read_file_as_bytes(str(file_path))
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
        return int_to_text(value)
    except UnicodeDecodeError:
        return None


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
    path.parent.mkdir(parents=True, exist_ok=True)

    json_text = json.dumps(data, indent=4, ensure_ascii=False)
    path.write_text(json_text, encoding="utf-8")

    console.print(f"[green]✓ Đã lưu dữ liệu demo vào:[/green] {path}")


def print_timing_info(timings: dict[str, float]) -> None:
    """
    In thời gian xử lý các bước chính.
    """
    table = Table(title="[10] Thời gian xử lý")

    table.add_column("Bước", style="cyan")
    table.add_column("Thời gian", style="white")

    for name, elapsed in timings.items():
        table.add_row(name, f"{elapsed:.6f} giây")

    console.print()
    console.print(table)


def print_manual_attack_result(
    recovered_m: int,
    recovered_text: str | None,
    output_file: str | None = None,
) -> None:
    """
    In kết quả cho chế độ attack thủ công.

    Ở chế độ này ta không biết original M,
    nên không gọi print_final_result().
    """
    table = Table(title="[9] Kết quả khôi phục")

    table.add_column("Tên", style="cyan")
    table.add_column("Giá trị", style="white")

    table.add_row("Recovered M", format_int(recovered_m))

    if recovered_text is not None:
        table.add_row("Recovered text", recovered_text)
    else:
        table.add_row(
            "Recovered text", "<không decode UTF-8 hoặc không yêu cầu decode>"
        )

    if output_file is not None:
        table.add_row("Output file", output_file)

    console.print()
    console.print(table)


def run_demo(args: argparse.Namespace) -> None:
    """
    Chạy demo tự động:

    1. Nhận message.
    2. Sinh n dùng chung.
    3. Tạo hai public key khác e.
    4. Mã hóa cùng một message.
    5. Tấn công Common Modulus Attack.
    6. In toàn bộ trace.
    """
    timings: dict[str, float] = {}
    total_start = time.perf_counter()

    print_title("DEMO TỰ ĐỘNG: RSA COMMON MODULUS ATTACK")

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
            'Ví dụ: python -m src.main demo --message "HELLO" --bits 512'
        ) from exc

    start = time.perf_counter()
    c1 = rsa_encrypt_int(message_int, e1, n)
    c2 = rsa_encrypt_int(message_int, e2, n)
    timings["Mã hóa C1, C2"] = time.perf_counter() - start

    start = time.perf_counter()
    recovered_m, trace = common_modulus_attack_pp2(c1, c2, e1, e2, n)
    timings["Common Modulus Attack"] = time.perf_counter() - start

    recovered_text = recover_text_safely(recovered_m)

    if args.output_file is not None:
        recovered_bytes = int_to_bytes(recovered_m, length=len(message_bytes))
        write_bytes_to_file(recovered_bytes, args.output_file)

    print_modulus_info(modulus_info)
    print_keys_info(key1, key2)
    print_message_info(message_display, message_int)
    print_encryption_info(message_int, c1, c2, e1, e2, n)
    print_attack_trace(trace)
    print_final_result(message_int, recovered_m, recovered_text)

    if args.output_file is not None:
        console.print(
            f"[green]✓ Đã ghi dữ liệu khôi phục ra:[/green] {args.output_file}"
        )

    timings["Tổng thời gian"] = time.perf_counter() - total_start
    print_timing_info(timings)

    demo_json = {
        "mode": "demo",
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


def run_attack(args: argparse.Namespace) -> None:
    """
    Chạy attack thủ công.

    Người dùng nhập:
        n, e1, e2, c1, c2

    Chương trình khôi phục M nếu điều kiện Common Modulus Attack thỏa.
    """
    timings: dict[str, float] = {}

    print_title("ATTACK THỦ CÔNG: RSA COMMON MODULUS ATTACK")

    start = time.perf_counter()
    recovered_m, trace = common_modulus_attack_pp2(
        c1=args.c1,
        c2=args.c2,
        e1=args.e1,
        e2=args.e2,
        n=args.n,
    )
    timings["Common Modulus Attack"] = time.perf_counter() - start

    recovered_text: str | None = None

    if args.decode_text:
        recovered_text = recover_text_safely(recovered_m)

    if args.output_file is not None:
        if args.output_length is None:
            recovered_bytes = int_to_bytes(recovered_m)
        else:
            recovered_bytes = int_to_bytes(recovered_m, length=args.output_length)

        write_bytes_to_file(recovered_bytes, args.output_file)

    print_attack_trace(trace)
    print_manual_attack_result(
        recovered_m=recovered_m,
        recovered_text=recovered_text,
        output_file=args.output_file,
    )
    print_timing_info(timings)


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
        help="Chạy demo tự động: sinh key, mã hóa, tấn công, khôi phục message.",
    )

    message_group = demo_parser.add_mutually_exclusive_group()

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

    demo_parser.add_argument(
        "--bits",
        type=int,
        default=512,
        help="Độ dài mong muốn của modulus n. Mặc định: 512.",
    )

    demo_parser.add_argument(
        "--save-json",
        type=str,
        default=None,
        help="Nếu truyền, chương trình sẽ lưu bộ dữ liệu demo ra JSON.",
    )

    demo_parser.add_argument(
        "--output-file",
        type=str,
        default=None,
        help="Nếu truyền, ghi dữ liệu khôi phục ra file.",
    )

    demo_parser.set_defaults(func=run_demo)

    attack_parser = subparsers.add_parser(
        "attack",
        help="Chạy attack thủ công với n, e1, e2, c1, c2.",
    )

    attack_parser.add_argument(
        "--n",
        type=parse_int,
        required=True,
        help="Modulus RSA dùng chung.",
    )

    attack_parser.add_argument(
        "--e1",
        type=parse_int,
        required=True,
        help="Public exponent thứ nhất.",
    )

    attack_parser.add_argument(
        "--e2",
        type=parse_int,
        required=True,
        help="Public exponent thứ hai.",
    )

    attack_parser.add_argument(
        "--c1",
        type=parse_int,
        required=True,
        help="Ciphertext thứ nhất.",
    )

    attack_parser.add_argument(
        "--c2",
        type=parse_int,
        required=True,
        help="Ciphertext thứ hai.",
    )

    attack_parser.add_argument(
        "--decode-text",
        action="store_true",
        help="Thử decode recovered M về text UTF-8.",
    )

    attack_parser.add_argument(
        "--output-file",
        type=str,
        default=None,
        help="Nếu truyền, ghi recovered M ra file dạng bytes.",
    )

    attack_parser.add_argument(
        "--output-length",
        type=int,
        default=None,
        help="Số byte khi ghi output-file. Hữu ích nếu dữ liệu gốc có byte 0 ở đầu.",
    )

    attack_parser.set_defaults(func=run_attack)

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
