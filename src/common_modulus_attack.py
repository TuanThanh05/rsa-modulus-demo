"""
common_modulus_attack.py

Triển khai kỹ thuật RSA Common Modulus Attack.

Kịch bản:
- Cùng một bản rõ m được mã hóa thành c1, c2.
- Hai bản mã dùng chung modulus n.
- Hai public exponent e1, e2 khác nhau và gcd(e1, e2) = 1.

Công thức:
    c1 = m^e1 mod n
    c2 = m^e2 mod n

Dùng Extended Euclidean Algorithm tìm a, b:
    a*e1 + b*e2 = 1

Suy ra:
    m = c1^a * c2^b mod n

Nếu a hoặc b âm, cần dùng nghịch đảo modulo.
"""

from .number_theory import gcd
from .number_theory import extended_gcd
from .number_theory import mod_inverse


def validate_attack_inputs(
    c1: int,
    c2: int,
    e1: int,
    e2: int,
    n: int,
) -> None:
    """
    Kiểm tra dữ liệu đầu vào cho Common Modulus Attack.

    Args:
        c1: Bản mã thứ nhất.
        c2: Bản mã thứ hai.
        e1: Public exponent thứ nhất.
        e2: Public exponent thứ hai.
        n: Modulus RSA dùng chung.

    Returns:
        None

    Raises:
        ValueError: Nếu input không hợp lệ.
    """
    if n <= 1:
        raise ValueError("n phải là số nguyên lớn hơn 1")

    if e1 <= 1:
        raise ValueError("e1 phải là số nguyên lớn hơn 1")

    if e2 <= 1:
        raise ValueError("e2 phải là số nguyên lớn hơn 1")

    if e1 == e2:
        raise ValueError("e1 và e2 phải khác nhau")

    if not (0 <= c1 < n):
        raise ValueError("c1 phải thỏa 0 <= c1 < n")

    if not (0 <= c2 < n):
        raise ValueError("c2 phải thỏa 0 <= c2 < n")


def handle_negative_power(c: int, exponent: int, n: int) -> int:
    """
    Tính c^exponent mod n, kể cả khi exponent âm.

    Nếu exponent >= 0:
        c^exponent mod n

    Nếu exponent < 0:
        c^exponent mod n
        = (c^-1)^abs(exponent) mod n

    Args:
        c: Cơ số, thường là c1 hoặc c2.
        exponent: Số mũ Bézout, có thể âm.
        n: Modulus RSA.

    Returns:
        int: Giá trị c^exponent mod n.

    Raises:
        ValueError: Nếu cần nghịch đảo modulo nhưng c không có inverse modulo n.
    """
    if n <= 1:
        raise ValueError("n phải là số nguyên lớn hơn 1")

    if not (0 <= c < n):
        raise ValueError("c phải thỏa 0 <= c < n")

    if exponent >= 0:
        return pow(c, exponent, n)

    try:
        inverse_c = mod_inverse(c, n)
    except ValueError as exc:
        raise ValueError(
            "Không thể xử lý số mũ âm vì c không có nghịch đảo modulo n"
        ) from exc

    return pow(inverse_c, abs(exponent), n)


def compute_signed_power_with_trace(
    c: int,
    exponent: int,
    n: int,
    label: str,
) -> tuple[int, dict[str, int | str | bool]]:
    """
    Tính c^exponent mod n và trả thêm trace để hiển thị.

    Args:
        c: Bản mã c1 hoặc c2.
        exponent: Số mũ Bézout tương ứng.
        n: Modulus RSA.
        label: Nhãn để ghi trace, ví dụ "C1" hoặc "C2".

    Returns:
        tuple:
            (
                result,
                trace
            )

        Trong đó result là int, trace là dict mô tả cách tính.
    """
    if exponent >= 0:
        result = pow(c, exponent, n)

        trace = {
            "label": label,
            "original_base": c,
            "original_exponent": exponent,
            "used_inverse": False,
            "base_used_for_power": c,
            "positive_exponent": exponent,
            "result": result,
        }

        return result, trace

    inverse_c = mod_inverse(c, n)
    positive_exponent = abs(exponent)
    result = pow(inverse_c, positive_exponent, n)

    trace = {
        "label": label,
        "original_base": c,
        "original_exponent": exponent,
        "used_inverse": True,
        "inverse_base": inverse_c,
        "base_used_for_power": inverse_c,
        "positive_exponent": positive_exponent,
        "result": result,
    }

    return result, trace


def common_modulus_attack(
    c1: int,
    c2: int,
    e1: int,
    e2: int,
    n: int,
) -> tuple[int, dict[str, int | str | bool | dict]]:
    """
    Thực hiện RSA Common Modulus Attack.

    Điều kiện:
        c1 = m^e1 mod n
        c2 = m^e2 mod n
        gcd(e1, e2) = 1

    Args:
        c1: Bản mã thứ nhất.
        c2: Bản mã thứ hai.
        e1: Public exponent thứ nhất.
        e2: Public exponent thứ hai.
        n: Modulus RSA dùng chung.

    Returns:
        tuple:
            (
                recovered_m,
                trace
            )

        recovered_m:
            Bản rõ dạng số nguyên đã khôi phục.

        trace:
            Dictionary chứa các bước trung gian để display.py in ra.

    Raises:
        ValueError:
            Nếu input không hợp lệ hoặc gcd(e1, e2) != 1.
    """
    validate_attack_inputs(c1, c2, e1, e2, n)

    gcd_e1_e2 = gcd(e1, e2)

    if gcd_e1_e2 != 1:
        raise ValueError(
            "Không thể tấn công bằng Common Modulus Attack vì gcd(e1, e2) != 1"
        )

    g, a, b = extended_gcd(e1, e2)

    if g != 1:
        raise ValueError("Không thể tấn công vì Extended GCD không trả về gcd = 1")

    part1, part1_trace = compute_signed_power_with_trace(
        c=c1,
        exponent=a,
        n=n,
        label="C1",
    )

    part2, part2_trace = compute_signed_power_with_trace(
        c=c2,
        exponent=b,
        n=n,
        label="C2",
    )

    recovered_m = (part1 * part2) % n

    trace = {
        "attack_name": "RSA Common Modulus Attack",
        "n": n,
        "c1": c1,
        "c2": c2,
        "e1": e1,
        "e2": e2,
        "gcd_e1_e2": gcd_e1_e2,
        "bezout_a": a,
        "bezout_b": b,
        "bezout_check": a * e1 + b * e2,
        "formula": "M = C1^a * C2^b mod n",
        "part1": part1,
        "part2": part2,
        "part1_trace": part1_trace,
        "part2_trace": part2_trace,
        "recovered_m": recovered_m,
    }

    return recovered_m, trace
