from Number_theory.number_theory import *
from Validate.validate_attack import validate_attack_inputs
import time

def compute_signed_power_with_trace(c, exponent, n):
    if exponent >= 0:
        result = pow(c, exponent, n)

        trace = {
            "original_base": c,
            "original_exponent": exponent,
            "used_inverse": False,
            "base_used_for_power": c,
            "result": result,
        }

        return result, trace

    inverse_c = mod_inverse(c, n)
    positive_exponent = abs(exponent)
    result = pow(inverse_c, positive_exponent, n)

    trace = {
        "original_base": c,
        "original_exponent": exponent,
        "used_inverse": True,
        "inverse_base": inverse_c,
        "base_used_for_power": inverse_c,
        "result": result,
    }

    return result, trace


def common_modulus_attack( c1, c2, e1, e2, n):
    trace = {}
    timing = {}
    total_start = time.perf_counter()
    validate_attack_inputs(c1, c2, e1, e2, n)

    start_check = time.perf_counter()
    gcd_e1_e2 = gcd(e1, e2)
    if gcd_e1_e2 != 1:
        raise ValueError("Không thể tấn công modulus n số chung vì e1 và e2 không là số nguyên tố cùng nhau!")
    timing["gcd"] = time.perf_counter() - start_check
    trace["gcd"] = gcd_e1_e2

    start_ex_gcd = time.perf_counter()
    g, a, b = extended_gcd(e1, e2)
    timing["ex_gcd"] = time.perf_counter() - start_ex_gcd
    trace["a"] = a
    trace["b"] = b

    start_mod1 = time.perf_counter()
    part1, part1_trace = compute_signed_power_with_trace( c=c1, exponent=a, n=n)
    timing["c1modn"] = time.perf_counter() - start_mod1
    trace["resultc1"] = part1
    trace["trace_resultc1"] = part1_trace

    start_mod2 = time.perf_counter()    
    part2, part2_trace = compute_signed_power_with_trace(c=c2, exponent=b, n=n,)
    timing["c2modn"] = time.perf_counter() - start_mod2
    trace["resultc2"] = part2
    trace["trace_resultc2"] = part2_trace

    start_mod = time.perf_counter()
    recovered_m = (part1 * part2) % n
    timing["mmodn"] = time.perf_counter()- start_mod
    timing["total_time"] = time.perf_counter() - total_start

    trace["timing"] = timing
    return recovered_m, trace
