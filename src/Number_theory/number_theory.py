def gcd(a, b):
    a = abs(a)
    b = abs(b)

    while b != 0:
        r = a % b
        a = b
        b = r

    return a


def extended_gcd(a, b):
    old_r = a
    r = b
    old_x = 1
    x = 0
    old_y = 0
    y = 1

    while r != 0:
        q = old_r // r
        new_r = old_r - q * r
        new_x = old_x - q * x
        new_y = old_y - q * y
        old_r = r
        r = new_r
        old_x = x
        x = new_x
        old_y = y
        y = new_y
    if old_r < 0:
        old_r = -old_r
        old_x = -old_x
        old_y = -old_y

    return old_r, old_x, old_y


def mod_inverse(a, n):
    g, x, y = extended_gcd(a, n)
    if g != 1:
        raise ValueError(f"{a} không có nghịch đảo modulo {n}")
    inverse = x % n
    return inverse


def is_coprime(a, b):
    result = gcd(a, b)
    if result == 1:
        return True
    return False
