import pytest

from src.rsa_core import generate_two_keys_with_shared_n
from src.rsa_core import rsa_encrypt_int

from src.common_modulus_attack import validate_attack_inputs
from src.common_modulus_attack import handle_negative_power
from src.common_modulus_attack import common_modulus_attack


def test_validate_attack_inputs_accepts_valid_input():
    validate_attack_inputs(
        c1=140,
        c2=30,
        e1=5,
        e2=7,
        n=247,
    )


def test_validate_attack_inputs_rejects_invalid_n():
    with pytest.raises(ValueError):
        validate_attack_inputs(
            c1=140,
            c2=30,
            e1=5,
            e2=7,
            n=1,
        )


def test_handle_negative_power_positive_exponent():
    result = handle_negative_power(
        c=140,
        exponent=3,
        n=247,
    )

    assert result == 77


def test_handle_negative_power_negative_exponent():
    result = handle_negative_power(
        c=30,
        exponent=-2,
        n=247,
    )

    assert result == 87


def test_common_modulus_attack_recovers_known_example():
    n = 247
    e1 = 5
    e2 = 7
    c1 = 140
    c2 = 30

    recovered_m, trace = common_modulus_attack(c1, c2, e1, e2, n)

    assert recovered_m == 30
    assert trace["recovered_m"] == 30


def test_common_modulus_attack_trace_contains_expected_values():
    n = 247
    e1 = 5
    e2 = 7
    c1 = 140
    c2 = 30

    recovered_m, trace = common_modulus_attack(c1, c2, e1, e2, n)

    assert recovered_m == 30
    assert trace["attack_name"] == "RSA Common Modulus Attack"
    assert trace["gcd_e1_e2"] == 1
    assert trace["bezout_check"] == 1
    assert trace["formula"] == "M = C1^a * C2^b mod n"

    assert trace["bezout_a"] == 3
    assert trace["bezout_b"] == -2

    assert trace["part1"] == 77
    assert trace["part2"] == 87
    assert (trace["part1"] * trace["part2"]) % n == 30


def test_common_modulus_attack_rejects_non_coprime_exponents():
    with pytest.raises(ValueError):
        common_modulus_attack(
            c1=10,
            c2=20,
            e1=6,
            e2=10,
            n=77,
        )


def test_common_modulus_attack_works_with_generated_rsa_data():
    data = generate_two_keys_with_shared_n(32)

    n = data["modulus_info"]["n"]

    e1 = data["key1"]["e"]
    e2 = data["key2"]["e"]

    m = 42

    c1 = rsa_encrypt_int(m, e1, n)
    c2 = rsa_encrypt_int(m, e2, n)

    recovered_m, trace = common_modulus_attack(c1, c2, e1, e2, n)

    assert recovered_m == m
    assert trace["recovered_m"] == m
    assert trace["gcd_e1_e2"] == 1
    assert trace["bezout_check"] == 1
