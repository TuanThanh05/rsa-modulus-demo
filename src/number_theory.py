"""
number_theory.py

Các hàm lý thuyết số nền tảng dùng cho RSA và Common Modulus Attack.
File này không phụ thuộc thư viện ngoài.
"""


def gcd(a: int, b: int) -> int:
    """
    Tính ước chung lớn nhất không âm của a và b.

    Examples:
        gcd(84, 30) -> 6
        gcd(84, -30) -> 6
        gcd(0, 7) -> 7
    """
    a = abs(a)
    b = abs(b)

    while b != 0:
        r = a % b
        a = b
        b = r

    return a


def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    """
    Thuật toán Euclid mở rộng.

    Returns:
        (g, x, y), trong đó:
            g = gcd(a, b)
            x*a + y*b = g

    Example:
        extended_gcd(67, 12) -> (1, -5, 28)
        Vì:
            -5*67 + 28*12 = 1
    """
    old_r = a
    r = b

    old_x = 1
    x = 0

    old_y = 0
    y = 1

    while r != 0:
        q = old_r // r

        # Lưu giá trị mới của phần dư
        new_r = old_r - q * r

        # Lưu hệ số mới ứng với a
        new_x = old_x - q * x

        # Lưu hệ số mới ứng với b
        new_y = old_y - q * y

        # Cập nhật phần dư
        old_r = r
        r = new_r

        # Cập nhật hệ số của a
        old_x = x
        x = new_x

        # Cập nhật hệ số của b
        old_y = y
        y = new_y

    if old_r < 0:
        old_r = -old_r
        old_x = -old_x
        old_y = -old_y

    return old_r, old_x, old_y


def mod_inverse(a: int, n: int) -> int:
    """
    Tìm nghịch đảo modulo của a theo modulo n.

    Returns:
        x sao cho:
            a*x ≡ 1 mod n

    Raises:
        ValueError: Nếu gcd(a, n) != 1.
    """
    g, x, y = extended_gcd(a, n)

    if g != 1:
        raise ValueError(f"{a} không có nghịch đảo modulo {n}")

    inverse = x % n

    return inverse


def is_coprime(a: int, b: int) -> bool:
    """
    Kiểm tra a và b có nguyên tố cùng nhau không.
    """
    result = gcd(a, b)

    if result == 1:
        return True

    return False
