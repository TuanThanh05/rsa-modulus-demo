"""
display.py

Các hàm hiển thị dữ liệu demo RSA Common Modulus Attack ra terminal.

File này không thực hiện tính toán mật mã chính.
File này nhận dữ liệu đã có từ:
- rsa_core.py
- common_modulus_attack.py
- file_codec.py

rồi in ra màn hình cho dễ quan sát.

Dùng thư viện rich để terminal nhìn rõ ràng hơn.
"""

from __future__ import annotations

from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.rule import Rule
from rich.syntax import Syntax
from rich.table import Table

console = Console()


def format_int(value: int | str | bool | None) -> str:
    return str(value)


def print_rule(title: str) -> None:
    console.print()
    console.print(Rule(title, style="cyan"))


def print_formula(title: str, formula: str) -> None:
    console.print()
    console.print(Panel(Syntax(formula, "text", word_wrap=True), title=title))


def print_title(title: str) -> None:
    console.print()
    console.print(
        Panel(
            title,
            title="RSA Common Modulus Demo",
            border_style="cyan",
        )
    )


def make_table(title: str) -> Table:
    return Table(
        title=title,
        show_lines=True,
        expand=True,
    )


def add_name_value_columns(table: Table) -> None:
    table.add_column("Tên", style="cyan", overflow="fold", no_wrap=False)
    table.add_column("Giá trị", style="white", overflow="fold", no_wrap=False)


def print_modulus_info(modulus_info: dict[str, int]) -> None:
    print_rule("[1] Sinh modulus chung")

    table = make_table("[1] Sinh modulus chung N = p × q")

    table.add_column("Tên", style="cyan", overflow="fold", no_wrap=False)
    table.add_column("Giá trị", style="white", overflow="fold", no_wrap=False)
    table.add_column("Ý nghĩa", style="green", overflow="fold", no_wrap=False)

    p = modulus_info["p"]
    q = modulus_info["q"]
    n = modulus_info["n"]
    phi = modulus_info["phi"]

    table.add_row("p", format_int(p), "Số nguyên tố thứ nhất")
    table.add_row("q", format_int(q), "Số nguyên tố thứ hai")
    table.add_row("N", format_int(n), "Modulus dùng chung")
    table.add_row("φ(N)", format_int(phi), "φ(N) = (p - 1) × (q - 1)")

    console.print(table)


def print_keys_info(
    key1: dict[str, int | tuple[int, int]],
    key2: dict[str, int | tuple[int, int]],
    key1_label: str = "key1",
    key2_label: str = "key2",
) -> None:
    print_rule("[2] Tạo hai cặp khóa RSA dùng chung N")

    table = make_table("[2] Tạo hai cặp khóa RSA dùng chung modulus N")

    table.add_column("Khóa", style="cyan", overflow="fold", no_wrap=False)
    table.add_column("N", style="white", overflow="fold", no_wrap=False)
    table.add_column("e", style="yellow", overflow="fold", no_wrap=False)
    table.add_column("d", style="magenta", overflow="fold", no_wrap=False)
    table.add_column("Ghi chú", style="green", overflow="fold", no_wrap=False)

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
        f"{key1_label}_public_key = (N, e)",
    )

    table.add_row(
        key2_label,
        format_int(n2),
        format_int(e2),
        format_int(d2),
        f"{key2_label}_public_key = (N, e)",
    )

    console.print(table)

    if n1 == n2:
        console.print("[green]✓ Hai khóa đang dùng chung cùng một modulus N.[/green]")
    else:
        console.print("[red]✗ Hai khóa không dùng chung modulus N.[/red]")


def print_message_info(
    message_text: str,
    message_int: int,
) -> None:
    print_rule("[3] Bản rõ ban đầu")

    table = make_table("[3] Bản rõ ban đầu")

    table.add_column("Dạng", style="cyan", overflow="fold", no_wrap=False)
    table.add_column("Giá trị", style="white", overflow="fold", no_wrap=False)

    table.add_row("Text/File display", message_text)
    table.add_row("Integer M", format_int(message_int))
    table.add_row("Số bit của M", format_int(message_int.bit_length()))

    console.print(table)


def print_encryption_info(
    message_int: int,
    c1: int,
    c2: int,
    e1: int,
    e2: int,
    n: int,
) -> None:
    print_rule("[4] Mã hóa cùng bản rõ bằng hai public key")

    table = make_table("[4] Mã hóa cùng bản rõ bằng hai public key")

    table.add_column("Dữ liệu/Công thức", style="cyan", overflow="fold", no_wrap=False)
    table.add_column("Kết quả", style="white", overflow="fold", no_wrap=False)

    formula_1 = f"C1 = M^{e1} mod N"
    formula_2 = f"C2 = M^{e2} mod N"

    table.add_row("M", format_int(message_int))
    table.add_row("N", format_int(n))
    table.add_row("e1", format_int(e1))
    table.add_row("e2", format_int(e2))
    table.add_row(formula_1, format_int(c1))
    table.add_row(formula_2, format_int(c2))

    console.print(table)

    formula_text = (
        "C1 = M^e1 mod N\n"
        "C2 = M^e2 mod N\n\n"
        f"C1 = M^{e1} mod N\n"
        f"C2 = M^{e2} mod N"
    )
    print_formula("Công thức mã hóa", formula_text)


def print_pp1_encryption_info(
    message_int: int,
    ciphertext: int,
    victim_e: int,
    n: int,
) -> None:
    print_rule("[4] Mã hóa bản rõ bằng public key của victim")

    table = make_table("[4] Mã hóa bản rõ bằng public key của victim")

    table.add_column("Công thức", style="cyan", overflow="fold", no_wrap=False)
    table.add_column("Kết quả", style="white", overflow="fold", no_wrap=False)

    formula = f"C = M^{victim_e} mod N"

    table.add_row("M", format_int(message_int))
    table.add_row("N", format_int(n))
    table.add_row("victim_e", format_int(victim_e))
    table.add_row(formula, format_int(ciphertext))

    console.print(table)


def print_attack_inputs_pp2(trace: dict[str, Any]) -> None:
    print_rule("[5] Dữ liệu attacker biết - PP2")

    table = make_table("[5] Dữ liệu attacker biết - PP2")

    table.add_column("Tên", style="cyan", overflow="fold", no_wrap=False)
    table.add_column("Giá trị", style="white", overflow="fold", no_wrap=False)
    table.add_column("Ý nghĩa", style="green", overflow="fold", no_wrap=False)

    table.add_row("N", format_int(trace["n"]), "Modulus RSA dùng chung")
    table.add_row("e1", format_int(trace["e1"]), "Public exponent thứ nhất")
    table.add_row("e2", format_int(trace["e2"]), "Public exponent thứ hai")
    table.add_row("C1", format_int(trace["c1"]), "Bản mã thứ nhất")
    table.add_row("C2", format_int(trace["c2"]), "Bản mã thứ hai")

    console.print(table)


def build_extended_gcd_steps(a: int, b: int) -> list[dict[str, int | str]]:
    steps: list[dict[str, int | str]] = []

    r_values = [a, b]
    s_values = [1, 0]
    t_values = [0, 1]

    steps.append(
        {
            "i": 0,
            "r_i_minus_2": "-",
            "r_i_minus_1": "-",
            "q": "-",
            "r_i": a,
            "s_i": 1,
            "t_i": 0,
            "check": f"1 × {a} + 0 × {b} = {a}",
        }
    )

    steps.append(
        {
            "i": 1,
            "r_i_minus_2": "-",
            "r_i_minus_1": "-",
            "q": "-",
            "r_i": b,
            "s_i": 0,
            "t_i": 1,
            "check": f"0 × {a} + 1 × {b} = {b}",
        }
    )

    i = 2

    while r_values[i - 1] != 0:
        r_i_minus_2 = r_values[i - 2]
        r_i_minus_1 = r_values[i - 1]

        q = r_i_minus_2 // r_i_minus_1
        r_i = r_i_minus_2 - q * r_i_minus_1
        s_i = s_values[i - 2] - q * s_values[i - 1]
        t_i = t_values[i - 2] - q * t_values[i - 1]

        check_value = s_i * a + t_i * b
        check = f"{s_i} × {a} + {t_i} × {b} = {check_value}"

        steps.append(
            {
                "i": i,
                "r_i_minus_2": r_i_minus_2,
                "r_i_minus_1": r_i_minus_1,
                "q": q,
                "r_i": r_i,
                "s_i": s_i,
                "t_i": t_i,
                "check": check,
            }
        )

        r_values.append(r_i)
        s_values.append(s_i)
        t_values.append(t_i)

        i = i + 1

    return steps


def print_extended_gcd_table_pp2(trace: dict[str, Any]) -> None:
    e1 = trace["e1"]
    e2 = trace["e2"]
    steps = build_extended_gcd_steps(e1, e2)

    print_rule("[6] Bảng Euclid mở rộng tìm hệ số Bézout")

    table = make_table("[6] Thuật toán Euclid mở rộng cho e1 và e2")

    table.add_column("i", justify="right", style="cyan", overflow="fold")
    table.add_column("rᵢ₋₂", justify="right", style="white", overflow="fold")
    table.add_column("rᵢ₋₁", justify="right", style="white", overflow="fold")
    table.add_column("qᵢ₋₁", justify="right", style="yellow", overflow="fold")
    table.add_column("rᵢ", justify="right", style="white", overflow="fold")
    table.add_column("sᵢ", justify="right", style="magenta", overflow="fold")
    table.add_column("tᵢ", justify="right", style="magenta", overflow="fold")
    table.add_column(
        "Kiểm tra: sᵢ × e1 + tᵢ × e2 = rᵢ",
        style="green",
        overflow="fold",
        no_wrap=False,
    )

    for step in steps:
        table.add_row(
            format_int(step["i"]),
            format_int(step["r_i_minus_2"]),
            format_int(step["r_i_minus_1"]),
            format_int(step["q"]),
            format_int(step["r_i"]),
            format_int(step["s_i"]),
            format_int(step["t_i"]),
            format_int(step["check"]),
        )

    console.print(table)

    a = trace["bezout_a"]
    b = trace["bezout_b"]
    bezout_check = trace["bezout_check"]

    formula_text = (
        f"gcd(e1, e2) = gcd({e1}, {e2}) = {trace['gcd_e1_e2']}\n\n"
        f"Hệ số Bézout tìm được:\n"
        f"a = {a}\n"
        f"b = {b}\n\n"
        f"Kiểm tra:\n"
        f"({a}) × ({e1}) + ({b}) × ({e2}) = {bezout_check}"
    )

    print_formula("Kết quả Euclid mở rộng", formula_text)


def print_bezout_step_pp2(trace: dict[str, Any]) -> None:
    print_rule("[6] Kết quả hệ số Bézout")

    e1 = trace["e1"]
    e2 = trace["e2"]
    gcd_e1_e2 = trace["gcd_e1_e2"]
    a = trace["bezout_a"]
    b = trace["bezout_b"]
    bezout_check = trace["bezout_check"]

    table = make_table("[6] Tìm hệ số Bézout bằng Extended Euclidean Algorithm")

    table.add_column("Biểu thức", style="cyan", overflow="fold", no_wrap=False)
    table.add_column("Giá trị", style="white", overflow="fold", no_wrap=False)

    table.add_row("gcd(e1, e2)", format_int(gcd_e1_e2))
    table.add_row("a", format_int(a))
    table.add_row("b", format_int(b))
    table.add_row("a × e1 + b × e2", format_int(bezout_check))

    console.print(table)

    console.print(
        f"[green]✓ Ta có: ({a}) × ({e1}) + ({b}) × ({e2}) = {bezout_check}[/green]"
    )


def print_power_trace(power_trace: dict[str, Any]) -> None:
    label = power_trace["label"]
    original_base = power_trace["original_base"]
    original_exponent = power_trace["original_exponent"]
    used_inverse = power_trace["used_inverse"]
    base_used_for_power = power_trace["base_used_for_power"]
    positive_exponent = power_trace["positive_exponent"]
    result = power_trace["result"]

    print_rule(f"[7] Xử lý lũy thừa của {label}")

    table = make_table(f"[7] Xử lý lũy thừa của {label}")

    table.add_column("Tên", style="cyan", overflow="fold", no_wrap=False)
    table.add_column("Giá trị", style="white", overflow="fold", no_wrap=False)

    table.add_row("Cơ số ban đầu", format_int(original_base))
    table.add_row("Số mũ ban đầu", format_int(original_exponent))

    if used_inverse:
        inverse_base = power_trace["inverse_base"]

        table.add_row("Số mũ âm?", "Có")
        table.add_row(f"{label}^(-1) mod N", format_int(inverse_base))
        table.add_row("Cơ số dùng để tính pow", format_int(base_used_for_power))
        table.add_row("Số mũ dương mới", format_int(positive_exponent))
    else:
        table.add_row("Số mũ âm?", "Không")
        table.add_row("Cơ số dùng để tính pow", format_int(base_used_for_power))
        table.add_row("Số mũ dương", format_int(positive_exponent))

    table.add_row("Kết quả", format_int(result))

    console.print(table)

    if used_inverse:
        formula_text = (
            f"{label}^{original_exponent} mod N\n"
            f"= ({label}^(-1))^{positive_exponent} mod N\n"
            f"= ({base_used_for_power})^{positive_exponent} mod N\n"
            f"= {result}"
        )
    else:
        formula_text = (
            f"{label}^{original_exponent} mod N\n"
            f"= {base_used_for_power}^{positive_exponent} mod N\n"
            f"= {result}"
        )

    print_formula(f"Công thức xử lý {label}", formula_text)


def print_recovery_step_pp2(trace: dict[str, Any]) -> None:
    print_rule("[8] Khôi phục bản rõ PP2")

    part1 = trace["part1"]
    part2 = trace["part2"]
    n = trace["n"]
    recovered_m = trace["recovered_m"]

    table = make_table("[8] Khôi phục bản rõ - PP2")

    table.add_column("Công thức/Giá trị", style="cyan", overflow="fold", no_wrap=False)
    table.add_column("Kết quả", style="white", overflow="fold", no_wrap=False)

    table.add_row("part1 = C1^a mod N", format_int(part1))
    table.add_row("part2 = C2^b mod N", format_int(part2))
    table.add_row("N", format_int(n))
    table.add_row("M = (part1 × part2) mod N", format_int(recovered_m))

    console.print(table)

    formula_text = (
        "M = C1^a × C2^b mod N\n"
        "M = (part1 × part2) mod N\n\n"
        f"M = ({part1} × {part2}) mod {n}\n"
        f"M = {recovered_m}"
    )

    print_formula("Công thức khôi phục bản rõ", formula_text)


def print_attack_trace_pp2(trace: dict[str, Any]) -> None:
    print_title(trace["attack_name"])

    print_attack_inputs_pp2(trace)
    print_extended_gcd_table_pp2(trace)
    print_bezout_step_pp2(trace)

    part1_trace = trace["part1_trace"]
    part2_trace = trace["part2_trace"]

    print_power_trace(part1_trace)
    print_power_trace(part2_trace)

    print_recovery_step_pp2(trace)


def print_attack_inputs_pp1(trace: dict[str, Any]) -> None:
    print_rule("[5] Dữ liệu attacker biết - PP1")

    table = make_table("[5] Dữ liệu attacker biết - PP1")

    table.add_column("Tên", style="cyan", overflow="fold", no_wrap=False)
    table.add_column("Giá trị", style="white", overflow="fold", no_wrap=False)
    table.add_column("Ý nghĩa", style="green", overflow="fold", no_wrap=False)

    table.add_row("N", format_int(trace["n"]), "Modulus dùng chung")
    table.add_row("ciphertext", format_int(trace["ciphertext"]), "Bản mã cần giải")
    table.add_row(
        "victim_e",
        format_int(trace["victim_e"]),
        "Public exponent của victim",
    )
    table.add_row(
        "attacker_e",
        format_int(trace["attacker_e"]),
        "Public exponent của attacker",
    )
    table.add_row(
        "attacker_d",
        format_int(trace["attacker_d"]),
        "Private exponent của attacker",
    )

    console.print(table)


def print_pp1_t_step(trace: dict[str, Any]) -> None:
    print_rule("[6] Đặt t trong PP1")

    attacker_e = trace["attacker_e"]
    attacker_d = trace["attacker_d"]
    initial_t = trace["initial_t"]

    table = make_table("[6] Đặt t = attacker_e × attacker_d - 1")

    table.add_column("Biểu thức", style="cyan", overflow="fold", no_wrap=False)
    table.add_column("Giá trị", style="white", overflow="fold", no_wrap=False)

    table.add_row("attacker_e", format_int(attacker_e))
    table.add_row("attacker_d", format_int(attacker_d))
    table.add_row("t = attacker_e × attacker_d - 1", format_int(initial_t))

    console.print(table)


def print_pp1_steps(trace: dict[str, Any]) -> None:
    print_rule("[7] Tìm private exponent của victim")

    table = make_table("[7] Tìm private exponent của victim")

    table.add_column("Lần", style="cyan", overflow="fold")
    table.add_column("current_t", style="white", overflow="fold", no_wrap=False)
    table.add_column("gcd(current_t, victim_e)", style="yellow", overflow="fold")
    table.add_column("r", style="magenta", overflow="fold", no_wrap=False)
    table.add_column("s", style="magenta", overflow="fold", no_wrap=False)
    table.add_column("r × t + s × e", style="green", overflow="fold", no_wrap=False)
    table.add_column("next_t / result", style="white", overflow="fold", no_wrap=False)

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

    console.print(table)


def print_recovery_step_pp1(trace: dict[str, Any]) -> None:
    print_rule("[8] Giải mã bằng private exponent khôi phục được - PP1")

    ciphertext = trace["ciphertext"]
    n = trace["n"]
    recovered_victim_d = trace["recovered_victim_d"]
    recovered_m = trace["recovered_m"]

    table = make_table("[8] Giải mã bằng private exponent khôi phục được - PP1")

    table.add_column("Công thức", style="cyan", overflow="fold", no_wrap=False)
    table.add_column("Giá trị", style="white", overflow="fold", no_wrap=False)

    table.add_row("recovered_victim_d", format_int(recovered_victim_d))
    table.add_row("ciphertext", format_int(ciphertext))
    table.add_row("N", format_int(n))
    table.add_row("M = ciphertext^recovered_victim_d mod N", format_int(recovered_m))

    console.print(table)

    formula_text = (
        "M = ciphertext^recovered_victim_d mod N\n\n"
        f"M = {ciphertext}^{recovered_victim_d} mod {n}\n"
        f"M = {recovered_m}"
    )

    print_formula("Công thức khôi phục PP1", formula_text)


def print_attack_trace_pp1(trace: dict[str, Any]) -> None:
    print_title(trace["attack_name"])

    print_attack_inputs_pp1(trace)
    print_pp1_t_step(trace)
    print_pp1_steps(trace)
    print_recovery_step_pp1(trace)


def print_attack_trace(trace: dict[str, Any]) -> None:
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
    print_rule("[9] Kết quả cuối cùng")

    table = make_table("[9] Kết quả cuối cùng")

    table.add_column("Tên", style="cyan", overflow="fold", no_wrap=False)
    table.add_column("Giá trị", style="white", overflow="fold", no_wrap=False)

    table.add_row("Original M", format_int(original_message_int))
    table.add_row("Recovered M", format_int(recovered_message_int))

    if recovered_text is not None:
        table.add_row("Recovered text", recovered_text)
    else:
        table.add_row("Recovered text", "<không decode được UTF-8>")

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
    print_rule("[9] Kết quả khôi phục")

    table = make_table("[9] Kết quả khôi phục")

    table.add_column("Tên", style="cyan", overflow="fold", no_wrap=False)
    table.add_column("Giá trị", style="white", overflow="fold", no_wrap=False)

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

    console.print(table)


def print_timing_info(timings: dict[str, float]) -> None:
    print_rule("[10] Thời gian xử lý")

    table = make_table("[10] Thời gian xử lý")

    table.add_column("Bước", style="cyan", overflow="fold", no_wrap=False)
    table.add_column("Thời gian", style="white", overflow="fold", no_wrap=False)

    for name, elapsed in timings.items():
        table.add_row(name, f"{elapsed:.6f} giây")

    console.print(table)


def prompt_text(label: str) -> str:
    return Prompt.ask(label)