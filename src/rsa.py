"""
rsa.py

File kiểm thử riêng cho thuật toán RSA cơ bản.

File này chỉ dùng để kiểm tra:
- Sinh khóa RSA
- Chuyển bản rõ sang số nguyên
- Mã hóa RSA
- Giải mã RSA
- So sánh bản rõ ban đầu và bản rõ khôi phục

Chạy từ thư mục gốc project:

    python -m src.rsa auto --message "HELLO PTIT" --bits 1024

    python -m src.rsa manual --p 61 --q 53 --e 17 --message "A"

    python -m src.rsa manual --n 3233 --e 17 --d 2753 --message "A"

    python -m src.rsa manual --n 3233 --d 2753 --ciphertext 2790
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.rule import Rule
from rich.syntax import Syntax
from rich.table import Table

# Cho phép file chạy được cả hai kiểu:
# 1. python -m src.rsa
# 2. python src/rsa.py
SRC_DIR = Path(__file__).resolve().parent

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

try:
    from .file_codec import ensure_message_fits_modulus
    from .file_codec import int_to_text
    from .file_codec import read_file_as_bytes
    from .file_codec import text_to_int
    from .file_codec import bytes_to_int
    from .number_theory import gcd
    from .number_theory import mod_inverse
    from .rsa_core import choose_public_exponent
    from .rsa_core import generate_rsa_key_with_shared_n
    from .rsa_core import generate_shared_modulus
    from .rsa_core import rsa_decrypt_int
    from .rsa_core import rsa_encrypt_int
except ImportError:
    from file_codec import ensure_message_fits_modulus
    from file_codec import int_to_text
    from file_codec import read_file_as_bytes
    from file_codec import text_to_int
    from file_codec import bytes_to_int
    from number_theory import gcd
    from number_theory import mod_inverse
    from rsa_core import choose_public_exponent
    from rsa_core import generate_rsa_key_with_shared_n
    from rsa_core import generate_shared_modulus
    from rsa_core import rsa_decrypt_int
    from rsa_core import rsa_encrypt_int


console = Console()

DEFAULT_MESSAGE = "HELLO PTIT - RSA TEST"


def parse_int(value: str) -> int:
    """
    Chuyển chuỗi nhập vào thành số nguyên.

    Hỗ trợ:
    - Số thập phân: 3233
    - Số hex: 0xca1
    - Số nhị phân: 0b110010100001
    """
    try:
        return int(value, 0)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            f"Không chuyển được '{value}' thành số nguyên."
        ) from exc


def prompt_int_if_missing(value: int | None, label: str) -> int:
    """
    Nếu đã có giá trị thì dùng luôn.
    Nếu chưa có thì hỏi người dùng nhập.
    """
    if value is not None:
        return value

    raw_value = Prompt.ask(label)

    return parse_int(raw_value)


def format_value(value: Any) -> str:
    """
    Chuyển giá trị sang chuỗi để hiển thị.

    Không rút gọn số lớn.
    """
    return str(value)


def make_table(title: str) -> Table:
    """
    Tạo bảng rich mặc định.
    """
    return Table(
        title=title,
        show_lines=True,
        expand=True,
    )


def print_title(title: str) -> None:
    """
    In tiêu đề chính.
    """
    console.print()
    console.print(
        Panel(
            title,
            title="RSA Test",
            border_style="cyan",
        )
    )


def print_rule(title: str) -> None:
    """
    In đường phân cách.
    """
    console.print()
    console.print(Rule(title, style="cyan"))


def print_formula(title: str, formula: str) -> None:
    """
    In công thức dạng text.
    """
    console.print()
    console.print(
        Panel(
            Syntax(formula, "text", word_wrap=True),
            title=title,
            border_style="green",
        )
    )


def safe_int_to_text(value: int) -> str | None:
    """
    Thử chuyển số nguyên về text UTF-8.

    Nếu không decode được thì trả về None.
    """
    try:
        return int_to_text(value)
    except UnicodeDecodeError:
        return None


def load_plaintext_from_args(args: argparse.Namespace) -> tuple[str, bytes, int]:
    """
    Lấy bản rõ từ --m, --message hoặc --file.

    Trả về:
    - message_display
    - message_bytes
    - message_int
    """
    if args.m is not None:
        message_int = args.m
        message_bytes = b""
        message_display = "<bản rõ nhập trực tiếp dạng số nguyên>"

        return message_display, message_bytes, message_int

    if args.file is not None:
        file_path = Path(args.file)
        message_bytes = read_file_as_bytes(file_path)
        message_int = bytes_to_int(message_bytes)

        try:
            message_display = message_bytes.decode("utf-8")
        except UnicodeDecodeError:
            message_display = (
                f"<file: {file_path}, {len(message_bytes)} bytes, "
                "không hiển thị được dạng UTF-8>"
            )

        return message_display, message_bytes, message_int

    message_text = args.message

    if message_text is None:
        message_text = Prompt.ask("Nhập bản rõ text", default=DEFAULT_MESSAGE)

    message_bytes = message_text.encode("utf-8")
    message_int = text_to_int(message_text)

    return message_text, message_bytes, message_int


def print_modulus_step(modulus_info: dict[str, int]) -> None:
    """
    In bước sinh p, q, N, phi.
    """
    print_rule("[1] Tham số modulus RSA")

    table = make_table("[1] Tham số modulus RSA")

    table.add_column("Tên", style="cyan", overflow="fold", no_wrap=False)
    table.add_column("Giá trị", style="white", overflow="fold", no_wrap=False)
    table.add_column("Ý nghĩa", style="green", overflow="fold", no_wrap=False)

    p = modulus_info.get("p")
    q = modulus_info.get("q")
    n = modulus_info["n"]
    phi = modulus_info.get("phi")

    if p is not None:
        table.add_row("p", format_value(p), "Số nguyên tố thứ nhất")

    if q is not None:
        table.add_row("q", format_value(q), "Số nguyên tố thứ hai")

    table.add_row("N", format_value(n), "Modulus RSA")

    if phi is not None:
        table.add_row("φ(N)", format_value(phi), "φ(N) = (p - 1) × (q - 1)")
        table.add_row("Kiểm tra N = p × q", format_value(p * q == n), "Đúng nếu p, q hợp lệ")
        table.add_row(
            "Kiểm tra φ(N)",
            format_value(phi == (p - 1) * (q - 1)),
            "Đúng nếu φ(N) được tính chính xác",
        )

    console.print(table)


def print_key_step(n: int, e: int, d: int, phi: int | None = None) -> None:
    """
    In khóa công khai và khóa bí mật.
    """
    print_rule("[2] Khóa RSA")

    table = make_table("[2] Khóa RSA")

    table.add_column("Thành phần", style="cyan", overflow="fold", no_wrap=False)
    table.add_column("Giá trị", style="white", overflow="fold", no_wrap=False)
    table.add_column("Ý nghĩa", style="green", overflow="fold", no_wrap=False)

    table.add_row("Public key", f"(N, e) = ({n}, {e})", "Khóa công khai")
    table.add_row("Private key", f"(N, d) = ({n}, {d})", "Khóa bí mật")
    table.add_row("N", format_value(n), "Modulus")
    table.add_row("e", format_value(e), "Số mũ công khai")
    table.add_row("d", format_value(d), "Số mũ bí mật")

    if phi is not None:
        table.add_row("gcd(e, φ(N))", format_value(gcd(e, phi)), "Phải bằng 1")
        table.add_row(
            "e × d mod φ(N)",
            format_value((e * d) % phi),
            "Phải bằng 1 nếu d là nghịch đảo modulo của e",
        )

    console.print(table)


def print_plaintext_step(
    message_display: str,
    message_bytes: bytes,
    message_int: int,
    n: int,
) -> None:
    """
    In bước chuyển bản rõ sang số nguyên.
    """
    print_rule("[3] Chuyển bản rõ sang số nguyên")

    table = make_table("[3] Chuyển bản rõ sang số nguyên")

    table.add_column("Dạng", style="cyan", overflow="fold", no_wrap=False)
    table.add_column("Giá trị", style="white", overflow="fold", no_wrap=False)

    table.add_row("Bản rõ hiển thị", message_display)

    if message_bytes != b"":
        table.add_row("Bản rõ dạng bytes", format_value(message_bytes))
        table.add_row("Số byte", format_value(len(message_bytes)))
    else:
        table.add_row("Bản rõ dạng bytes", "<không có vì nhập trực tiếp số nguyên>")
        table.add_row("Số byte", "<không xác định>")

    table.add_row("Bản rõ dạng số nguyên M", format_value(message_int))
    table.add_row("Số bit của M", format_value(message_int.bit_length()))
    table.add_row("Điều kiện 0 ≤ M < N", format_value(0 <= message_int < n))

    console.print(table)


def print_encrypt_step(m: int, e: int, n: int, c: int) -> None:
    """
    In bước mã hóa RSA.
    """
    print_rule("[4] Mã hóa RSA")

    table = make_table("[4] Mã hóa RSA")

    table.add_column("Dữ liệu/Công thức", style="cyan", overflow="fold", no_wrap=False)
    table.add_column("Giá trị", style="white", overflow="fold", no_wrap=False)

    table.add_row("M", format_value(m))
    table.add_row("e", format_value(e))
    table.add_row("N", format_value(n))
    table.add_row("C = M^e mod N", format_value(c))
    table.add_row("Kiểm tra C == pow(M, e, N)", format_value(c == pow(m, e, n)))

    console.print(table)

    formula = (
        "C = M^e mod N\n\n"
        f"C = {m}^{e} mod {n}\n"
        f"C = {c}"
    )

    print_formula("Công thức mã hóa", formula)


def print_decrypt_step(c: int, d: int, n: int, recovered_m: int) -> None:
    """
    In bước giải mã RSA.
    """
    print_rule("[5] Giải mã RSA")

    table = make_table("[5] Giải mã RSA")

    table.add_column("Dữ liệu/Công thức", style="cyan", overflow="fold", no_wrap=False)
    table.add_column("Giá trị", style="white", overflow="fold", no_wrap=False)

    table.add_row("C", format_value(c))
    table.add_row("d", format_value(d))
    table.add_row("N", format_value(n))
    table.add_row("Recovered M = C^d mod N", format_value(recovered_m))
    table.add_row(
        "Kiểm tra Recovered M == pow(C, d, N)",
        format_value(recovered_m == pow(c, d, n)),
    )

    console.print(table)

    formula = (
        "Recovered M = C^d mod N\n\n"
        f"Recovered M = {c}^{d} mod {n}\n"
        f"Recovered M = {recovered_m}"
    )

    print_formula("Công thức giải mã", formula)


def print_final_step(
    original_m: int | None,
    recovered_m: int,
    recovered_text: str | None,
) -> None:
    """
    In kết quả cuối cùng.
    """
    print_rule("[6] Kết quả kiểm tra RSA")

    table = make_table("[6] Kết quả kiểm tra RSA")

    table.add_column("Tên", style="cyan", overflow="fold", no_wrap=False)
    table.add_column("Giá trị", style="white", overflow="fold", no_wrap=False)

    if original_m is not None:
        table.add_row("Original M", format_value(original_m))

    table.add_row("Recovered M", format_value(recovered_m))

    if recovered_text is not None:
        table.add_row("Recovered text", recovered_text)
    else:
        table.add_row("Recovered text", "<không decode được UTF-8>")

    if original_m is not None:
        table.add_row("So sánh Original M và Recovered M", format_value(original_m == recovered_m))

    console.print(table)

    if original_m is not None and original_m == recovered_m:
        console.print("[bold green]✓ RSA hoạt động đúng: giải mã khôi phục đúng bản rõ ban đầu.[/bold green]")
    elif original_m is not None:
        console.print("[bold red]✗ RSA lỗi: bản rõ khôi phục không trùng bản rõ ban đầu.[/bold red]")
    else:
        console.print("[bold green]✓ Đã giải mã ciphertext thành số nguyên Recovered M.[/bold green]")


def print_timing_step(timings: dict[str, float]) -> None:
    """
    In thời gian xử lý.
    """
    print_rule("[7] Thời gian xử lý")

    table = make_table("[7] Thời gian xử lý")

    table.add_column("Bước", style="cyan", overflow="fold", no_wrap=False)
    table.add_column("Thời gian", style="white", overflow="fold", no_wrap=False)

    for name, elapsed in timings.items():
        table.add_row(name, f"{elapsed:.6f} giây")

    console.print(table)


def run_auto(args: argparse.Namespace) -> None:
    """
    Chạy kiểm thử RSA tự động.
    """
    timings: dict[str, float] = {}
    total_start = time.perf_counter()

    print_title("CHẾ ĐỘ AUTO: KIỂM THỬ RSA CƠ BẢN")

    message_display, message_bytes, message_int = load_plaintext_from_args(args)

    start = time.perf_counter()
    modulus_info = generate_shared_modulus(args.bits)
    timings["Sinh p, q, N, φ(N)"] = time.perf_counter() - start

    n = modulus_info["n"]
    phi = modulus_info["phi"]

    start = time.perf_counter()

    if args.e is None:
        e = choose_public_exponent(phi)
    else:
        e = args.e

    key_info = generate_rsa_key_with_shared_n(n, phi, e)

    timings["Tạo khóa RSA"] = time.perf_counter() - start

    e = key_info["e"]
    d = key_info["d"]

    ensure_message_fits_modulus(message_int, n)

    start = time.perf_counter()
    ciphertext = rsa_encrypt_int(message_int, e, n)
    timings["Mã hóa RSA"] = time.perf_counter() - start

    start = time.perf_counter()
    recovered_m = rsa_decrypt_int(ciphertext, d, n)
    timings["Giải mã RSA"] = time.perf_counter() - start

    recovered_text = safe_int_to_text(recovered_m)

    print_modulus_step(modulus_info)
    print_key_step(n, e, d, phi)
    print_plaintext_step(message_display, message_bytes, message_int, n)
    print_encrypt_step(message_int, e, n, ciphertext)
    print_decrypt_step(ciphertext, d, n, recovered_m)
    print_final_step(message_int, recovered_m, recovered_text)

    timings["Tổng thời gian"] = time.perf_counter() - total_start
    print_timing_step(timings)


def build_manual_key(args: argparse.Namespace) -> tuple[dict[str, int], int, int, int, int | None]:
    """
    Tạo thông tin khóa cho chế độ thủ công.

    Có hai cách:
    - Nhập p, q, e: chương trình tự tính N, φ(N), d.
    - Nhập N, e, d: chương trình dùng trực tiếp khóa đã có.
    """
    if args.p is not None or args.q is not None:
        p = prompt_int_if_missing(args.p, "Nhập số nguyên tố p")
        q = prompt_int_if_missing(args.q, "Nhập số nguyên tố q")
        e = prompt_int_if_missing(args.e, "Nhập số mũ công khai e")

        n = p * q
        phi = (p - 1) * (q - 1)
        d = mod_inverse(e, phi)

        modulus_info = {
            "p": p,
            "q": q,
            "n": n,
            "phi": phi,
        }

        return modulus_info, n, e, d, phi

    n = prompt_int_if_missing(args.n, "Nhập modulus N")
    e = prompt_int_if_missing(args.e, "Nhập số mũ công khai e")
    d = prompt_int_if_missing(args.d, "Nhập số mũ bí mật d")

    modulus_info = {
        "n": n,
    }

    return modulus_info, n, e, d, None


def run_manual(args: argparse.Namespace) -> None:
    """
    Chạy kiểm thử RSA thủ công.
    """
    timings: dict[str, float] = {}
    total_start = time.perf_counter()

    print_title("CHẾ ĐỘ MANUAL: KIỂM THỬ RSA THỦ CÔNG")

    start = time.perf_counter()
    modulus_info, n, e, d, phi = build_manual_key(args)
    timings["Chuẩn bị khóa RSA"] = time.perf_counter() - start

    if args.ciphertext is not None:
        ciphertext = args.ciphertext

        start = time.perf_counter()
        recovered_m = rsa_decrypt_int(ciphertext, d, n)
        timings["Giải mã RSA"] = time.perf_counter() - start

        recovered_text = safe_int_to_text(recovered_m)

        print_modulus_step(modulus_info)
        print_key_step(n, e, d, phi)
        print_decrypt_step(ciphertext, d, n, recovered_m)
        print_final_step(None, recovered_m, recovered_text)

        timings["Tổng thời gian"] = time.perf_counter() - total_start
        print_timing_step(timings)

        return

    message_display, message_bytes, message_int = load_plaintext_from_args(args)

    ensure_message_fits_modulus(message_int, n)

    start = time.perf_counter()
    ciphertext = rsa_encrypt_int(message_int, e, n)
    timings["Mã hóa RSA"] = time.perf_counter() - start

    start = time.perf_counter()
    recovered_m = rsa_decrypt_int(ciphertext, d, n)
    timings["Giải mã RSA"] = time.perf_counter() - start

    recovered_text = safe_int_to_text(recovered_m)

    print_modulus_step(modulus_info)
    print_key_step(n, e, d, phi)
    print_plaintext_step(message_display, message_bytes, message_int, n)
    print_encrypt_step(message_int, e, n, ciphertext)
    print_decrypt_step(ciphertext, d, n, recovered_m)
    print_final_step(message_int, recovered_m, recovered_text)

    timings["Tổng thời gian"] = time.perf_counter() - total_start
    print_timing_step(timings)


def add_plaintext_arguments(parser: argparse.ArgumentParser) -> None:
    """
    Thêm tham số nhập bản rõ.
    """
    plaintext_group = parser.add_mutually_exclusive_group()

    plaintext_group.add_argument(
        "--message",
        type=str,
        default=None,
        help="Bản rõ dạng text.",
    )

    plaintext_group.add_argument(
        "--file",
        type=str,
        default=None,
        help="Đường dẫn file bản rõ.",
    )

    plaintext_group.add_argument(
        "--m",
        type=parse_int,
        default=None,
        help="Bản rõ nhập trực tiếp dạng số nguyên.",
    )


def build_parser() -> argparse.ArgumentParser:
    """
    Tạo parser CLI.
    """
    parser = argparse.ArgumentParser(
        prog="python -m src.rsa",
        description="File kiểm thử RSA cơ bản: sinh khóa, mã hóa, giải mã.",
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    auto_parser = subparsers.add_parser(
        "auto",
        help="Tự sinh khóa RSA, mã hóa và giải mã.",
    )
    add_plaintext_arguments(auto_parser)
    auto_parser.add_argument(
        "--bits",
        type=int,
        default=1024,
        help="Độ dài modulus N. Mặc định: 1024.",
    )
    auto_parser.add_argument(
        "--e",
        type=parse_int,
        default=None,
        help="Số mũ công khai e. Nếu không nhập, chương trình tự chọn.",
    )
    auto_parser.set_defaults(func=run_auto)

    manual_parser = subparsers.add_parser(
        "manual",
        help="Nhập khóa RSA thủ công, mã hóa và giải mã.",
    )
    add_plaintext_arguments(manual_parser)

    manual_parser.add_argument(
        "--p",
        type=parse_int,
        default=None,
        help="Số nguyên tố p. Nếu nhập p và q, chương trình tự tính N, φ(N), d.",
    )
    manual_parser.add_argument(
        "--q",
        type=parse_int,
        default=None,
        help="Số nguyên tố q. Nếu nhập p và q, chương trình tự tính N, φ(N), d.",
    )
    manual_parser.add_argument(
        "--n",
        type=parse_int,
        default=None,
        help="Modulus N. Dùng khi đã có sẵn khóa.",
    )
    manual_parser.add_argument(
        "--e",
        type=parse_int,
        default=None,
        help="Số mũ công khai e.",
    )
    manual_parser.add_argument(
        "--d",
        type=parse_int,
        default=None,
        help="Số mũ bí mật d. Nếu nhập p, q, e thì có thể không cần nhập d.",
    )
    manual_parser.add_argument(
        "--ciphertext",
        type=parse_int,
        default=None,
        help="Nếu nhập ciphertext, chương trình chỉ giải mã ciphertext này.",
    )
    manual_parser.set_defaults(func=run_manual)

    return parser


def main() -> None:
    """
    Entry point chính.
    """
    parser = build_parser()
    args = parser.parse_args()

    try:
        args.func(args)
    except KeyboardInterrupt:
        console.print()
        console.print(
            Panel(
                "Đã hủy chương trình.",
                title="Dừng chương trình",
                border_style="yellow",
            )
        )
        raise SystemExit(130)
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