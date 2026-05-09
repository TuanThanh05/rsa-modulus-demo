import pytest

from src.number_theory import gcd
from src.number_theory import is_coprime

from src.rsa_core import generate_shared_modulus
from src.rsa_core import choose_public_exponent
from src.rsa_core import generate_rsa_key_with_shared_n
from src.rsa_core import rsa_encrypt_int
from src.rsa_core import rsa_decrypt_int
from src.rsa_core import generate_two_keys_with_shared_n


def test_generate_shared_modulus_returns_consistent_values():
    info = generate_shared_modulus(32)

    p = info["p"]
    q = info["q"]
    n = info["n"]
    phi = info["phi"]

    assert p != q
    assert n == p * q
    assert phi == (p - 1) * (q - 1)
    assert n.bit_length() in (31, 32)


def test_choose_public_exponent_returns_valid_e():
    phi = 160

    e = choose_public_exponent(phi)

    assert 1 < e < phi
    assert is_coprime(e, phi)


def test_choose_public_exponent_can_avoid_existing_e():
    phi = 160

    e1 = choose_public_exponent(phi)
    e2 = choose_public_exponent(
        phi,
        avoid={e1},
        coprime_with={e1},
    )

    assert e2 != e1
    assert is_coprime(e2, phi)
    assert is_coprime(e2, e1)


def test_generate_rsa_key_with_shared_n_returns_valid_key():
    p = 11
    q = 17
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 7

    key = generate_rsa_key_with_shared_n(n, phi, e)

    assert key["n"] == 187
    assert key["e"] == 7
    assert key["d"] == 23
    assert key["public_key"] == (187, 7)
    assert key["private_key"] == (187, 23)
    assert (key["e"] * key["d"]) % phi == 1


def test_rsa_encrypt_then_decrypt_recovers_message():
    p = 11
    q = 17
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 7

    key = generate_rsa_key_with_shared_n(n, phi, e)

    m = 42
    c = rsa_encrypt_int(m, key["e"], key["n"])
    recovered_m = rsa_decrypt_int(c, key["d"], key["n"])

    assert c == pow(m, e, n)
    assert recovered_m == m


def test_rsa_encrypt_rejects_message_not_less_than_n():
    n = 187
    e = 7
    m = 187

    with pytest.raises(ValueError):
        rsa_encrypt_int(m, e, n)


def test_generate_two_keys_with_shared_n_uses_same_n_and_coprime_exponents():
    data = generate_two_keys_with_shared_n(32)

    n = data["modulus_info"]["n"]
    phi = data["modulus_info"]["phi"]

    key1 = data["key1"]
    key2 = data["key2"]

    assert key1["n"] == n
    assert key2["n"] == n
    assert key1["e"] != key2["e"]

    assert gcd(key1["e"], phi) == 1
    assert gcd(key2["e"], phi) == 1
    assert gcd(key1["e"], key2["e"]) == 1

    assert (key1["e"] * key1["d"]) % phi == 1
    assert (key2["e"] * key2["d"]) % phi == 1
