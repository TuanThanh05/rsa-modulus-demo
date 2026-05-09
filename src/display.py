"""
display.py

Các hàm hiển thị dữ liệu demo RSA Common Modulus Attack ra terminal.

File này không thực hiện tính toán mật mã.
File này chỉ nhận dữ liệu đã có từ:
- rsa_core.py
- common_modulus_attack.py
- file_codec.py

rồi in ra màn hình cho dễ quan sát.

Dùng thư viện rich để terminal nhìn rõ ràng hơn.
"""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()


def format_int(value: int, max_digits: int = 80) -> str:
    """
    Chuyển số nguyên thành chuỗi để in ra màn hình.

    Nếu số quá dài, hàm sẽ rút gọn phần giữa để terminal dễ nhìn hơn.

    Args:
        value: Số nguyên cần hiển thị.
        max_digits: Số chữ số tối đa muốn hiển thị đầy đủ.

    Returns:
        str: Chuỗi biểu diễn số nguyên.
    """
    text = str(value)

    if len(text) <= max_digits:
        return text

    left_length = max_digits // 2
    right_length = max_digits // 2

    left_part = text[:left_length]
    right_part = text[-right_length:]

    result = f"{left_part} ... {right_part}"

    return result


def print_title(title: str) -> None:
    """
    In tiêu đề chính của một phần demo.

    Args:
        title: Nội dung tiêu đề.

    Returns:
        None
    """
    panel = Panel(
        title,
        title="RSA Common Modulus Demo",
        border_style="cyan",
    )

    console.print()
    console.print(panel)


def print_modulus_info(modulus_info: dict[str, int]) -> None:
    """
    In thông tin p, q, n, phi(n).

    Args:
        modulus_info: Dictionary chứa p, q, n, phi.

    Returns:
        None
    """
    table = Table(title="[1] Sinh modulus chung n = p * q")

    table.add_column("Tên", style="cyan")
    table.add_column("Giá trị", style="white")
    table.add_column("Ý nghĩa", style="green")

    p = modulus_info["p"]
    q = modulus_info["q"]
    n = modulus_info["n"]
    phi = modulus_info["phi"]

    table.add_row("p", format_int(p), "Số nguyên tố thứ nhất")
    table.add_row("q", format_int(q), "Số nguyên tố thứ hai")
    table.add_row("n", format_int(n), "Modulus dùng chung")
    table.add_row("phi", format_int(phi), "phi(n) = (p - 1) * (q - 1)")

    console.print()
    console.print(table)


def print_keys_info(
    key1: dict[str, int | tuple[int, int]],
    key2: dict[str, int | tuple[int, int]],
) -> None:
    """
    In thông tin hai cặp khóa RSA dùng chung n.

    Args:
        key1: Dictionary chứa khóa thứ nhất.
        key2: Dictionary chứa khóa thứ hai.

    Returns:
        None
    """
    table = Table(title="[2] Tạo hai public key dùng chung modulus n")

    table.add_column("Khóa", style="cyan")
    table.add_column("n", style="white")
    table.add_column("e", style="yellow")
    table.add_column("d", style="magenta")
    table.add_column("Ghi chú", style="green")

    n1 = key1["n"]
    e1 = key1["e"]
    d1 = key1["d"]

    n2 = key2["n"]
    e2 = key2["e"]
    d2 = key2["d"]

    table.add_row(
        "key1",
        format_int(n1),
        format_int(e1),
        format_int(d1),
        "public_key_1 = (n, e1)",
    )

    table.add_row(
        "key2",
        format_int(n2),
        format_int(e2),
        format_int(d2),
        "public_key_2 = (n, e2)",
    )

    console.print()
    console.print(table)

    if n1 == n2:
        console.print("[green]✓ Hai khóa đang dùng chung cùng một modulus n.[/green]")
    else:
        console.print("[red]✗ Hai khóa không dùng chung modulus n.[/red]")


def print_message_info(
    message_text: str,
    message_int: int,
) -> None:
    """
    In bản rõ ban đầu ở dạng text và dạng số nguyên.

    Args:
        message_text: Bản rõ dạng text.
        message_int: Bản rõ dạng số nguyên.

    Returns:
        None
    """
    table = Table(title="[3] Bản rõ ban đầu")

    table.add_column("Dạng", style="cyan")
    table.add_column("Giá trị", style="white")

    table.add_row("Text", message_text)
    table.add_row("Integer M", format_int(message_int))

    console.print()
    console.print(table)


def print_encryption_info(
    message_int: int,
    c1: int,
    c2: int,
    e1: int,
    e2: int,
    n: int,
) -> None:
    """
    In quá trình mã hóa cùng một bản rõ M bằng hai public exponent khác nhau.

    Args:
        message_int: Bản rõ dạng số nguyên M.
        c1: Bản mã thứ nhất.
        c2: Bản mã thứ hai.
        e1: Public exponent thứ nhất.
        e2: Public exponent thứ hai.
        n: Modulus dùng chung.

    Returns:
        None
    """
    table = Table(title="[4] Mã hóa cùng bản rõ bằng hai public key")

    table.add_column("Công thức", style="cyan")
    table.add_column("Kết quả", style="white")

    formula_1 = f"C1 = M^{e1} mod n"
    formula_2 = f"C2 = M^{e2} mod n"

    table.add_row("M", format_int(message_int))
    table.add_row("n", format_int(n))
    table.add_row(formula_1, format_int(c1))
    table.add_row(formula_2, format_int(c2))

    console.print()
    console.print(table)


def print_attack_inputs(trace: dict) -> None:
    """
    In dữ liệu mà attacker biết.

    Args:
        trace: Dictionary trace trả về từ common_modulus_attack.

    Returns:
        None
    """
    table = Table(title="[5] Dữ liệu attacker biết")

    table.add_column("Tên", style="cyan")
    table.add_column("Giá trị", style="white")

    table.add_row("n", format_int(trace["n"]))
    table.add_row("e1", format_int(trace["e1"]))
    table.add_row("e2", format_int(trace["e2"]))
    table.add_row("C1", format_int(trace["c1"]))
    table.add_row("C2", format_int(trace["c2"]))

    console.print()
    console.print(table)


def print_bezout_step(trace: dict) -> None:
    """
    In bước dùng Extended Euclidean Algorithm để tìm hệ số Bézout.

    Args:
        trace: Dictionary trace trả về từ common_modulus_attack.

    Returns:
        None
    """
    e1 = trace["e1"]
    e2 = trace["e2"]
    gcd_e1_e2 = trace["gcd_e1_e2"]
    a = trace["bezout_a"]
    b = trace["bezout_b"]
    bezout_check = trace["bezout_check"]

    table = Table(title="[6] Tìm hệ số Bézout bằng Extended Euclidean Algorithm")

    table.add_column("Biểu thức", style="cyan")
    table.add_column("Giá trị", style="white")

    table.add_row("gcd(e1, e2)", format_int(gcd_e1_e2))
    table.add_row("a", format_int(a))
    table.add_row("b", format_int(b))
    table.add_row("a*e1 + b*e2", format_int(bezout_check))

    console.print()
    console.print(table)

    console.print(
        f"[green]✓ Ta có: ({a})*({e1}) + ({b})*({e2}) = {bezout_check}[/green]"
    )


def print_power_trace(power_trace: dict) -> None:
    """
    In cách xử lý một lũy thừa C^exponent mod n.

    Hàm này đặc biệt hữu ích khi exponent âm,
    vì lúc đó chương trình phải dùng nghịch đảo modulo.

    Args:
        power_trace: Trace con, ví dụ trace["part1_trace"] hoặc trace["part2_trace"].

    Returns:
        None
    """
    label = power_trace["label"]
    original_base = power_trace["original_base"]
    original_exponent = power_trace["original_exponent"]
    used_inverse = power_trace["used_inverse"]
    base_used_for_power = power_trace["base_used_for_power"]
    positive_exponent = power_trace["positive_exponent"]
    result = power_trace["result"]

    table = Table(title=f"[7] Xử lý lũy thừa của {label}")

    table.add_column("Tên", style="cyan")
    table.add_column("Giá trị", style="white")

    table.add_row("Cơ số ban đầu", format_int(original_base))
    table.add_row("Số mũ ban đầu", format_int(original_exponent))

    if used_inverse:
        inverse_base = power_trace["inverse_base"]

        table.add_row("Số mũ âm?", "Có")
        table.add_row(f"{label}^-1 mod n", format_int(inverse_base))
        table.add_row("Cơ số dùng để tính pow", format_int(base_used_for_power))
        table.add_row("Số mũ dương mới", format_int(positive_exponent))
    else:
        table.add_row("Số mũ âm?", "Không")
        table.add_row("Cơ số dùng để tính pow", format_int(base_used_for_power))
        table.add_row("Số mũ dương", format_int(positive_exponent))

    table.add_row("Kết quả", format_int(result))

    console.print()
    console.print(table)


def print_recovery_step(trace: dict) -> None:
    """
    In bước khôi phục bản rõ M.

    Args:
        trace: Dictionary trace trả về từ common_modulus_attack.

    Returns:
        None
    """
    part1 = trace["part1"]
    part2 = trace["part2"]
    n = trace["n"]
    recovered_m = trace["recovered_m"]

    table = Table(title="[8] Khôi phục bản rõ")

    table.add_column("Công thức", style="cyan")
    table.add_column("Giá trị", style="white")

    table.add_row("part1", format_int(part1))
    table.add_row("part2", format_int(part2))
    table.add_row("(part1 * part2) mod n", format_int(recovered_m))

    console.print()
    console.print(table)

    console.print(
        f"[green]✓ Recovered M = ({part1} * {part2}) mod {n} = {recovered_m}[/green]"
    )


def print_attack_trace(trace: dict) -> None:
    """
    In toàn bộ quá trình Common Modulus Attack từ trace.

    Args:
        trace: Dictionary trace trả về từ common_modulus_attack.

    Returns:
        None
    """
    attack_name = trace["attack_name"]

    print_title(attack_name)

    print_attack_inputs(trace)
    print_bezout_step(trace)

    part1_trace = trace["part1_trace"]
    part2_trace = trace["part2_trace"]

    print_power_trace(part1_trace)
    print_power_trace(part2_trace)

    print_recovery_step(trace)


def print_final_result(
    original_message_int: int,
    recovered_message_int: int,
    recovered_text: str | None = None,
) -> None:
    """
    In kết quả cuối cùng của demo.

    Args:
        original_message_int: Bản rõ ban đầu dạng số nguyên.
        recovered_message_int: Bản rõ khôi phục dạng số nguyên.
        recovered_text: Text khôi phục nếu có.

    Returns:
        None
    """
    table = Table(title="[9] Kết quả cuối cùng")

    table.add_column("Tên", style="cyan")
    table.add_column("Giá trị", style="white")

    table.add_row("Original M", format_int(original_message_int))
    table.add_row("Recovered M", format_int(recovered_message_int))

    if recovered_text is not None:
        table.add_row("Recovered text", recovered_text)

    console.print()
    console.print(table)

    if original_message_int == recovered_message_int:
        console.print(
            "[bold green]✓ Tấn công thành công: bản rõ khôi phục trùng bản rõ ban đầu.[/bold green]"
        )
    else:
        console.print(
            "[bold red]✗ Tấn công thất bại: bản rõ khôi phục không trùng bản rõ ban đầu.[/bold red]"
        )
