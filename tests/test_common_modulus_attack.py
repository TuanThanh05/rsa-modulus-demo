import pytest

from src.rsa_core import generate_two_keys_with_shared_n
from src.rsa_core import rsa_encrypt_int

from src.common_modulus_attack import validate_attack_inputs
from src.common_modulus_attack import handle_negative_power
from src.common_modulus_attack import common_modulus_attack_pp1
from src.common_modulus_attack import common_modulus_attack_pp2


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


def test_common_modulus_attack_pp1_recovers_private_key_and_message():
    n = 253
    victim_e = 13
    attacker_e = 23
    attacker_d = 67
    ciphertext = 27

    recovered_victim_d, recovered_m, trace = common_modulus_attack_pp1(
        ciphertext=ciphertext,
        victim_e=victim_e,
        attacker_e=attacker_e,
        attacker_d=attacker_d,
        n=n,
    )

    assert recovered_victim_d == 237
    assert recovered_m == 25

    assert trace["attack_method"] == "PP1"
    assert trace["initial_t"] == 1540
    assert trace["recovered_victim_d"] == 237
    assert trace["recovered_m"] == 25


def test_common_modulus_attack_pp1_trace_contains_expected_values():
    n = 253
    victim_e = 13
    attacker_e = 23
    attacker_d = 67
    ciphertext = 27

    recovered_victim_d, recovered_m, trace = common_modulus_attack_pp1(
        ciphertext=ciphertext,
        victim_e=victim_e,
        attacker_e=attacker_e,
        attacker_d=attacker_d,
        n=n,
    )

    first_step = trace["steps"][0]

    assert recovered_victim_d == 237
    assert recovered_m == 25

    assert first_step["current_t"] == 1540
    assert first_step["victim_e"] == 13
    assert first_step["gcd_current_t_victim_e"] == 1
    assert first_step["bezout_check"] == 1
    assert first_step["recovered_victim_d"] == 237
    assert first_step["recovered_m"] == 25


def test_common_modulus_attack_pp2_alias_still_works():
    n = 247
    e1 = 5
    e2 = 7
    c1 = 140
    c2 = 30

    recovered_m_from_pp2, trace_pp2 = common_modulus_attack_pp2(
        c1=c1,
        c2=c2,
        e1=e1,
        e2=e2,
        n=n,
    )

    recovered_m_from_alias, trace_alias = common_modulus_attack(
        c1=c1,
        c2=c2,
        e1=e1,
        e2=e2,
        n=n,
    )

    assert recovered_m_from_pp2 == 30
    assert recovered_m_from_alias == 30

    assert trace_pp2["attack_method"] == "PP2"
    assert trace_alias["attack_method"] == "PP2"


def test_common_modulus_attack_pp1_rejects_invalid_ciphertext():
    with pytest.raises(ValueError):
        common_modulus_attack_pp1(
            ciphertext=253,
            victim_e=13,
            attacker_e=23,
            attacker_d=67,
            n=253,
        )
