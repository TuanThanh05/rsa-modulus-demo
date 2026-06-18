from sympy import randprime
from Number_theory.number_theory import gcd
from Number_theory.number_theory import is_coprime
from Number_theory.number_theory import mod_inverse

def generate_prime(bits):
    if bits < 4:
        raise ValueError("Bit không đủ lớn để sinh ra số nguyên tố!")
    lower = 2 ** (bits - 1)
    upper = 2**bits
    prime = randprime(lower, upper)
    prime = int(prime)
    return prime

def generate_shared_modulus(bits):
    if bits < 16:
        raise ValueError("Bit không đủ lớn để thực hiện chọn số nguyên tố!")
    
    p_bits = bits // 2
    q_bits = bits - p_bits
    p = generate_prime(p_bits)
    q = generate_prime(q_bits)
    while q == p:
        q = generate_prime(q_bits)
    n = p * q
    phi = (p - 1) * (q - 1)
    modulus_info = {"p": p, "q": q, "n": n, "phi": phi}
    return modulus_info

def choose_public_exponent(phi: int, avoid: set[int] | None = None, coprime_with: set[int] | None = None,) -> int:
    if phi <= 3:
        raise ValueError("Phi quá nhỏ không chọn được e hợp lệ!")
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
    raise ValueError("Không tìm được số e hợp lệ!")

def generate_rsa_key_with_shared_n( n, phi, e,):
    if n <= 0:
        raise ValueError("N phải là số nguyên dương!")
    if phi <= 0:
        raise ValueError("Phi phải là số nguyên dương!")
    if not (1 < e < phi):
        raise ValueError("E phải thuộc khoảng (1, n)!")
    gcd_result = gcd(e, phi)
    if gcd_result != 1:
        raise ValueError("E không là số nguyên tố cùng nhau với phi!")
    d = mod_inverse(e, phi)
    key_info = { "n": n, "e": e, "d": d, "public_key": (n, e), "private_key": (n, d)}
    return key_info

def rsa_encrypt_int(m, e, n):
    if not (0 <= m < n):
        raise ValueError("Bản rõ m phải thuộc khoảng [0, n)!")
    c = pow(m, e, n)
    return c

def rsa_decrypt_int(c, d, n):
    if not (0 <= c < n):
        raise ValueError("Bản mã c phải thuộc khoảng [0, n)!")
    m = pow(c, d, n)
    return m

def generate_two_keys_with_shared_n(bits):
    modulus_info = generate_shared_modulus(bits)
    n = modulus_info["n"]
    phi = modulus_info["phi"]
    e1 = choose_public_exponent(phi)
    e2 = choose_public_exponent(phi, avoid={e1}, coprime_with={e1})

    key1 = generate_rsa_key_with_shared_n(n, phi, e1)
    key2 = generate_rsa_key_with_shared_n(n, phi, e2)

    result = {"modulus_info": modulus_info, "key1": key1, "key2": key2 }

    return result
