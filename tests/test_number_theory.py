import pytest

from src.number_theory import gcd
from src.number_theory import extended_gcd
from src.number_theory import mod_inverse
from src.number_theory import is_coprime


def test_gcd_positive_numbers():
    assert gcd(84, 30) == 6


def test_gcd_with_negative_numbers():
    assert gcd(-84, 30) == 6
    assert gcd(84, -30) == 6
    assert gcd(-84, -30) == 6


def test_extended_gcd_returns_valid_bezout_identity():
    g, x, y = extended_gcd(67, 12)

    assert g == 1
    assert 67 * x + 12 * y == g


def test_mod_inverse_valid_case():
    assert mod_inverse(12, 67) == 28
    assert (12 * mod_inverse(12, 67)) % 67 == 1


def test_mod_inverse_invalid_case():
    with pytest.raises(ValueError):
        mod_inverse(6, 9)


def test_is_coprime_true():
    assert is_coprime(5, 7) is True


def test_is_coprime_false():
    assert is_coprime(6, 9) is False
