"""
rsa_core.py

Các hàm RSA cơ bản dùng để tạo dữ liệu demo cho Common Modulus Attack.

File này chỉ làm RSA bình thường:
- sinh p, q
- tính n, phi(n)
- chọn e
- tính d
- mã hóa số nguyên
- giải mã số nguyên

Lưu ý:
Đây là textbook RSA phục vụ học tập, không dùng cho bảo mật thực tế.
"""

from sympy import randprime

from .number_theory import gcd
from .number_theory import is_coprime
from .number_theory import mod_inverse


def generate_prime(bits: int) -> int:
    """
    Sinh một số nguyên tố có độ dài xấp xỉ 'bits' bit.

    Args:
        bits: Số bit mong muốn của số nguyên tố.

    Returns:
        int: Một số nguyên tố p sao cho p có khoảng 'bits' bit.

    Example:
        generate_prime(8) có thể trả về 197.
    """
    if bits < 4:
        raise ValueError("bits phải >= 4 để sinh số nguyên tố demo hợp lý")

    lower = 2 ** (bits - 1)
    upper = 2**bits

    prime = randprime(lower, upper)

    prime = int(prime)

    return prime


def generate_shared_modulus(bits: int) -> dict[str, int]:
    """
    Sinh p, q, n, phi(n) cho RSA.

    Trong đề tài Common Modulus Attack, n này sẽ được dùng chung
    cho nhiều public key khác nhau.

    Args:
        bits: Độ dài mong muốn của modulus n.

    Returns:
        dict[str, int]: Dictionary chứa p, q, n, phi.

    Output dạng:
        {
            "p": p,
            "q": q,
            "n": n,
            "phi": phi
        }
    """
    if bits < 16:
        raise ValueError("bits nên >= 16. Demo nhỏ quá dễ lỗi và không đại diện RSA.")

    prime_bits = bits // 2

    p = generate_prime(prime_bits)
    q = generate_prime(prime_bits)

    while q == p:
        q = generate_prime(prime_bits)

    n = p * q

    phi = (p - 1) * (q - 1)

    modulus_info = {
        "p": p,
        "q": q,
        "n": n,
        "phi": phi,
    }

    return modulus_info


def choose_public_exponent(
    phi: int,
    avoid: set[int] | None = None,
    coprime_with: set[int] | None = None,
) -> int:
    """
    Chọn số mũ công khai e hợp lệ cho RSA.

    Điều kiện RSA:
        1 < e < phi
        gcd(e, phi) = 1

    Điều kiện thêm cho Common Modulus Attack:
        Nếu đã có e1, khi chọn e2 nên đảm bảo gcd(e1, e2) = 1.

    Args:
        phi: Giá trị phi(n).
        avoid: Tập các e không muốn chọn lại.
        coprime_with: Tập các e mà e mới phải nguyên tố cùng nhau với chúng.

    Returns:
        int: Số mũ công khai e.
    """
    if phi <= 3:
        raise ValueError("phi quá nhỏ, không chọn được public exponent hợp lệ")

    if avoid is None:
        avoid = set()

    if coprime_with is None:
        coprime_with = set()

    common_candidates = [65537, 257, 17, 13, 11, 7, 5, 3]

    for e in common_candidates:
        if e in avoid:
            continue

        if not (1 < e < phi):
            continue

        if not is_coprime(e, phi):
            continue

        is_valid_with_other_exponents = True

        for other_e in coprime_with:
            if not is_coprime(e, other_e):
                is_valid_with_other_exponents = False
                break

        if is_valid_with_other_exponents:
            return e

    e = 3

    while e < phi:
        if e in avoid:
            e = e + 2
            continue

        if not is_coprime(e, phi):
            e = e + 2
            continue

        is_valid_with_other_exponents = True

        for other_e in coprime_with:
            if not is_coprime(e, other_e):
                is_valid_with_other_exponents = False
                break

        if is_valid_with_other_exponents:
            return e

        e = e + 2

    raise ValueError("Không tìm được public exponent hợp lệ")


def generate_rsa_key_with_shared_n(
    n: int,
    phi: int,
    e: int,
) -> dict[str, int | tuple[int, int]]:
    """
    Tạo một cặp khóa RSA với modulus n đã có sẵn.

    Args:
        n: Modulus RSA.
        phi: Giá trị phi(n).
        e: Public exponent.

    Returns:
        dict:
            {
                "n": n,
                "e": e,
                "d": d,
                "public_key": (n, e),
                "private_key": (n, d)
            }

    Ý nghĩa:
        public_key = (n, e)
        private_key = (n, d)
    """
    if n <= 0:
        raise ValueError("n phải là số nguyên dương")

    if phi <= 0:
        raise ValueError("phi phải là số nguyên dương")

    if not (1 < e < phi):
        raise ValueError("e phải thỏa 1 < e < phi")

    gcd_result = gcd(e, phi)

    if gcd_result != 1:
        raise ValueError("e không hợp lệ vì gcd(e, phi) != 1")

    d = mod_inverse(e, phi)

    key_info = {
        "n": n,
        "e": e,
        "d": d,
        "public_key": (n, e),
        "private_key": (n, d),
    }

    return key_info


def rsa_encrypt_int(m: int, e: int, n: int) -> int:
    """
    Mã hóa bản rõ dạng số nguyên bằng RSA.

    Công thức:
        c = m^e mod n

    Args:
        m: Bản rõ dạng số nguyên.
        e: Public exponent.
        n: Modulus.

    Returns:
        int: Bản mã c.
    """
    if not (0 <= m < n):
        raise ValueError("Bản rõ m phải thỏa 0 <= m < n")

    c = pow(m, e, n)

    return c


def rsa_decrypt_int(c: int, d: int, n: int) -> int:
    """
    Giải mã bản mã dạng số nguyên bằng RSA.

    Công thức:
        m = c^d mod n

    Args:
        c: Bản mã dạng số nguyên.
        d: Private exponent.
        n: Modulus.

    Returns:
        int: Bản rõ m.
    """
    if not (0 <= c < n):
        raise ValueError("Bản mã c phải thỏa 0 <= c < n")

    m = pow(c, d, n)

    return m


def generate_two_keys_with_shared_n(bits: int) -> dict:
    """
    Hàm tiện ích cho demo Common Modulus Attack.

    Sinh cùng một n nhưng tạo hai cặp khóa khác e:
        key1 = (n, e1), private d1
        key2 = (n, e2), private d2

    Args:
        bits: Độ dài mong muốn của modulus n.

    Returns:
        dict chứa modulus_info, key1, key2.
    """
    modulus_info = generate_shared_modulus(bits)

    n = modulus_info["n"]
    phi = modulus_info["phi"]

    e1 = choose_public_exponent(phi)

    e2 = choose_public_exponent(
        phi,
        avoid={e1},
        coprime_with={e1},
    )

    key1 = generate_rsa_key_with_shared_n(n, phi, e1)
    key2 = generate_rsa_key_with_shared_n(n, phi, e2)

    result = {
        "modulus_info": modulus_info,
        "key1": key1,
        "key2": key2,
    }

    return result
