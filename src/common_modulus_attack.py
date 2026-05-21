from .number_theory import extended_gcd
from .number_theory import gcd
from .number_theory import mod_inverse


def validate_attack_inputs_pp2(
    c1: int,
    c2: int,
    e1: int,
    e2: int,
    n: int,
) -> None:
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
    if n <= 1:
        raise ValueError("n phải là số nguyên lớn hơn 1")

    if not (0 <= c < n):
        raise ValueError("c phải thỏa 0 <= c < n")

    if exponent >= 0:
        result = pow(c, exponent, n)
        return result

    try:
        inverse_c = mod_inverse(c, n)
    except ValueError as exc:
        raise ValueError(
            "Không thể xử lý số mũ âm vì c không có nghịch đảo modulo n"
        ) from exc

    positive_exponent = abs(exponent)
    result = pow(inverse_c, positive_exponent, n)

    return result


def compute_signed_power_with_trace(
    c: int,
    exponent: int,
    n: int,
    label: str,
) -> tuple[int, dict[str, int | str | bool]]:
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


def common_modulus_attack_pp2(
    c1: int,
    c2: int,
    e1: int,
    e2: int,
    n: int,
) -> tuple[int, dict]:
    validate_attack_inputs_pp2(c1, c2, e1, e2, n)

    gcd_e1_e2 = gcd(e1, e2)

    if gcd_e1_e2 != 1:
        raise ValueError(
            "Không thể tấn công bằng Common Modulus Attack PP2 vì gcd(e1, e2) != 1"
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
        "attack_method": "PP2",
        "description": "Dùng hai bản mã của cùng một bản rõ với cùng modulus n để khôi phục m.",
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

validate_attack_inputs = validate_attack_inputs_pp2
common_modulus_attack = common_modulus_attack_pp2