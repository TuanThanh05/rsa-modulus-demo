from .number_theory import gcd
from .number_theory import extended_gcd
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


def validate_attack_inputs_pp1(
    ciphertext: int,
    victim_e: int,
    attacker_e: int,
    attacker_d: int,
    n: int,
) -> None:
    if n <= 1:
        raise ValueError("n phải là số nguyên lớn hơn 1")

    if victim_e <= 1:
        raise ValueError("victim_e phải là số nguyên lớn hơn 1")

    if attacker_e <= 1:
        raise ValueError("attacker_e phải là số nguyên lớn hơn 1")

    if attacker_d <= 1:
        raise ValueError("attacker_d phải là số nguyên lớn hơn 1")

    if victim_e == attacker_e:
        raise ValueError("victim_e và attacker_e nên khác nhau trong kịch bản PP1")

    if not (0 <= ciphertext < n):
        raise ValueError("ciphertext phải thỏa 0 <= ciphertext < n")


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


def common_modulus_attack_pp1(
    ciphertext: int,
    victim_e: int,
    attacker_e: int,
    attacker_d: int,
    n: int,
) -> tuple[int, int, dict[str, int | str | list[dict[str, int]]]]:
    validate_attack_inputs_pp1(
        ciphertext=ciphertext,
        victim_e=victim_e,
        attacker_e=attacker_e,
        attacker_d=attacker_d,
        n=n,
    )

    initial_t = attacker_e * attacker_d - 1

    if initial_t <= 0:
        raise ValueError("t = attacker_e * attacker_d - 1 phải là số dương")

    current_t = initial_t
    steps = []
    iteration = 1

    while current_t > 1:
        f = gcd(current_t, victim_e)

        g, r, s = extended_gcd(current_t, victim_e)

        step = {
            "iteration": iteration,
            "current_t": current_t,
            "victim_e": victim_e,
            "gcd_current_t_victim_e": f,
            "extended_gcd_g": g,
            "bezout_r": r,
            "bezout_s": s,
            "bezout_check": r * current_t + s * victim_e,
        }

        if f == 1:
            recovered_victim_d = s % current_t

            recovered_m = pow(ciphertext, recovered_victim_d, n)

            step["recovered_victim_d"] = recovered_victim_d
            step["recovered_m"] = recovered_m

            steps.append(step)

            trace = {
                "attack_name": "RSA Common Modulus Attack - PP1",
                "attack_method": "PP1",
                "description": "Dùng khóa công khai và khóa bí mật của attacker để tìm private exponent của victim.",
                "n": n,
                "ciphertext": ciphertext,
                "victim_e": victim_e,
                "attacker_e": attacker_e,
                "attacker_d": attacker_d,
                "initial_t": initial_t,
                "final_t": current_t,
                "recovered_victim_d": recovered_victim_d,
                "recovered_m": recovered_m,
                "steps": steps,
            }

            return recovered_victim_d, recovered_m, trace

        next_t = current_t // f

        step["next_t"] = next_t

        steps.append(step)

        current_t = next_t
        iteration = iteration + 1

    raise ValueError(
        "Không tìm được private exponent cho victim bằng PP1. "
        "Có thể dữ liệu đầu vào không đúng kịch bản dùng chung modulus."
    )


def common_modulus_attack_pp2(
    c1: int,
    c2: int,
    e1: int,
    e2: int,
    n: int,
) -> tuple[int, dict[str, int | str | bool | dict]]:
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

common_modulus_attack = common_modulus_attack_pp2
