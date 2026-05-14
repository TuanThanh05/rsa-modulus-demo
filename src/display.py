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
    key1_label: str = "key1",
    key2_label: str = "key2",
) -> None:
    """
    In thông tin hai cặp khóa RSA dùng chung n.
    """
    table = Table(title="[2] Tạo hai cặp khóa RSA dùng chung modulus n")

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
        key1_label,
        format_int(n1),
        format_int(e1),
        format_int(d1),
        f"{key1_label}_public_key = (n, e)",
    )

    table.add_row(
        key2_label,
        format_int(n2),
        format_int(e2),
        format_int(d2),
        f"{key2_label}_public_key = (n, e)",
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
    """
    table = Table(title="[3] Bản rõ ban đầu")

    table.add_column("Dạng", style="cyan")
    table.add_column("Giá trị", style="white")

    table.add_row("Text/File display", message_text)
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


def print_pp1_encryption_info(
    message_int: int,
    ciphertext: int,
    victim_e: int,
    n: int,
) -> None:
    """
    In quá trình mã hóa bản rõ M bằng public key của victim trong PP1.
    """
    table = Table(title="[4] Mã hóa bản rõ bằng public key của victim")

    table.add_column("Công thức", style="cyan")
    table.add_column("Kết quả", style="white")

    formula = f"C = M^{victim_e} mod n"

    table.add_row("M", format_int(message_int))
    table.add_row("n", format_int(n))
    table.add_row(formula, format_int(ciphertext))

    console.print()
    console.print(table)


def print_attack_inputs_pp2(trace: dict) -> None:
    """
    In dữ liệu attacker biết trong PP2.
    """
    table = Table(title="[5] Dữ liệu attacker biết - PP2")

    table.add_column("Tên", style="cyan")
    table.add_column("Giá trị", style="white")

    table.add_row("n", format_int(trace["n"]))
    table.add_row("e1", format_int(trace["e1"]))
    table.add_row("e2", format_int(trace["e2"]))
    table.add_row("C1", format_int(trace["c1"]))
    table.add_row("C2", format_int(trace["c2"]))

    console.print()
    console.print(table)


def print_bezout_step_pp2(trace: dict) -> None:
    """
    In bước dùng Extended Euclidean Algorithm để tìm hệ số Bézout trong PP2.
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


def print_recovery_step_pp2(trace: dict) -> None:
    """
    In bước khôi phục bản rõ M trong PP2.
    """
    part1 = trace["part1"]
    part2 = trace["part2"]
    n = trace["n"]
    recovered_m = trace["recovered_m"]

    table = Table(title="[8] Khôi phục bản rõ - PP2")

    table.add_column("Công thức", style="cyan")
    table.add_column("Giá trị", style="white")

    table.add_row("part1", format_int(part1))
    table.add_row("part2", format_int(part2))
    table.add_row("(part1 * part2) mod n", format_int(recovered_m))

    console.print()
    console.print(table)

    console.print(
        "[green]✓ Recovered M = "
        f"({format_int(part1)} * {format_int(part2)}) "
        f"mod {format_int(n)} = {format_int(recovered_m)}[/green]"
    )


def print_attack_trace_pp2(trace: dict) -> None:
    """
    In toàn bộ quá trình Common Modulus Attack PP2.
    """
    print_title(trace["attack_name"])

    print_attack_inputs_pp2(trace)
    print_bezout_step_pp2(trace)

    part1_trace = trace["part1_trace"]
    part2_trace = trace["part2_trace"]

    print_power_trace(part1_trace)
    print_power_trace(part2_trace)

    print_recovery_step_pp2(trace)


def print_attack_inputs_pp1(trace: dict) -> None:
    """
    In dữ liệu attacker biết trong PP1.
    """
    table = Table(title="[5] Dữ liệu attacker biết - PP1")

    table.add_column("Tên", style="cyan")
    table.add_column("Giá trị", style="white")
    table.add_column("Ý nghĩa", style="green")

    table.add_row("n", format_int(trace["n"]), "Modulus dùng chung")
    table.add_row("ciphertext", format_int(trace["ciphertext"]), "Bản mã cần giải")
    table.add_row(
        "victim_e", format_int(trace["victim_e"]), "Public exponent của victim"
    )
    table.add_row(
        "attacker_e", format_int(trace["attacker_e"]), "Public exponent của attacker"
    )
    table.add_row(
        "attacker_d", format_int(trace["attacker_d"]), "Private exponent của attacker"
    )

    console.print()
    console.print(table)


def print_pp1_t_step(trace: dict) -> None:
    """
    In bước đặt t = attacker_e * attacker_d - 1.
    """
    attacker_e = trace["attacker_e"]
    attacker_d = trace["attacker_d"]
    initial_t = trace["initial_t"]

    table = Table(title="[6] Đặt t = attacker_e * attacker_d - 1")

    table.add_column("Biểu thức", style="cyan")
    table.add_column("Giá trị", style="white")

    table.add_row("attacker_e", format_int(attacker_e))
    table.add_row("attacker_d", format_int(attacker_d))
    table.add_row("t = attacker_e * attacker_d - 1", format_int(initial_t))

    console.print()
    console.print(table)


def print_pp1_steps(trace: dict) -> None:
    """
    In các vòng lặp tìm private exponent của victim trong PP1.
    """
    table = Table(title="[7] Tìm private exponent của victim")

    table.add_column("Lần", style="cyan")
    table.add_column("current_t", style="white")
    table.add_column("gcd(current_t, victim_e)", style="yellow")
    table.add_column("r", style="magenta")
    table.add_column("s", style="magenta")
    table.add_column("r*t + s*e", style="green")
    table.add_column("next_t / result", style="white")

    steps = trace["steps"]

    for step in steps:
        iteration = step["iteration"]
        current_t = step["current_t"]
        gcd_value = step["gcd_current_t_victim_e"]
        r = step["bezout_r"]
        s = step["bezout_s"]
        bezout_check = step["bezout_check"]

        if "recovered_victim_d" in step:
            result_text = f"d_victim = {format_int(step['recovered_victim_d'])}"
        else:
            result_text = f"next_t = {format_int(step['next_t'])}"

        table.add_row(
            format_int(iteration),
            format_int(current_t),
            format_int(gcd_value),
            format_int(r),
            format_int(s),
            format_int(bezout_check),
            result_text,
        )

    console.print()
    console.print(table)


def print_recovery_step_pp1(trace: dict) -> None:
    """
    In bước giải mã bằng private exponent khôi phục được trong PP1.
    """
    ciphertext = trace["ciphertext"]
    n = trace["n"]
    recovered_victim_d = trace["recovered_victim_d"]
    recovered_m = trace["recovered_m"]

    table = Table(title="[8] Giải mã bằng private exponent khôi phục được - PP1")

    table.add_column("Công thức", style="cyan")
    table.add_column("Giá trị", style="white")

    table.add_row("recovered_victim_d", format_int(recovered_victim_d))
    table.add_row("ciphertext", format_int(ciphertext))
    table.add_row("n", format_int(n))
    table.add_row("M = ciphertext^recovered_victim_d mod n", format_int(recovered_m))

    console.print()
    console.print(table)

    console.print(
        "[green]✓ Recovered M = "
        f"{format_int(ciphertext)}^{format_int(recovered_victim_d)} "
        f"mod {format_int(n)} = {format_int(recovered_m)}[/green]"
    )


def print_attack_trace_pp1(trace: dict) -> None:
    """
    In toàn bộ quá trình Common Modulus Attack PP1.
    """
    print_title(trace["attack_name"])

    print_attack_inputs_pp1(trace)
    print_pp1_t_step(trace)
    print_pp1_steps(trace)
    print_recovery_step_pp1(trace)


def print_attack_trace(trace: dict) -> None:
    """
    In toàn bộ quá trình Common Modulus Attack từ trace.

    Hàm này tự nhận diện PP1 hoặc PP2 dựa vào trace["attack_method"].
    """
    attack_method = trace.get("attack_method")

    if attack_method == "PP1":
        print_attack_trace_pp1(trace)
        return

    if attack_method == "PP2":
        print_attack_trace_pp2(trace)
        return

    raise ValueError("Không nhận diện được attack_method trong trace")


def print_final_result(
    original_message_int: int,
    recovered_message_int: int,
    recovered_text: str | None = None,
) -> None:
    """
    In kết quả cuối cùng của demo.
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


def print_manual_attack_result(
    recovered_m: int,
    recovered_text: str | None = None,
    recovered_d: int | None = None,
    output_file: str | None = None,
) -> None:
    """
    In kết quả cho chế độ attack thủ công.

    Ở chế độ thủ công có thể không biết original M,
    nên không so sánh original và recovered.
    """
    table = Table(title="[9] Kết quả khôi phục")

    table.add_column("Tên", style="cyan")
    table.add_column("Giá trị", style="white")

    if recovered_d is not None:
        table.add_row("Recovered victim d", format_int(recovered_d))

    table.add_row("Recovered M", format_int(recovered_m))

    if recovered_text is not None:
        table.add_row("Recovered text", recovered_text)
    else:
        table.add_row(
            "Recovered text",
            "<không decode UTF-8 hoặc không yêu cầu decode>",
        )

    if output_file is not None:
        table.add_row("Output file", output_file)

    console.print()
    console.print(table)


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
