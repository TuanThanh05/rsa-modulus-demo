# number_theory.py

# `gcd(a, b)`

## Input

| Tham số | Kiểu dữ liệu | Ý nghĩa            |
| ------- | ------------ | ------------------ |
| `a`     | `int`        | Số nguyên thứ nhất |
| `b`     | `int`        | Số nguyên thứ hai  |

---

## Output

Trả về:

```python
int
```

Trong đó giá trị trả về là:

- Ước chung lớn nhất không âm của `a` và `b`

---

## Mô tả

## Tính ước chung lớn nhất không âm của hai số nguyên bằng thuật toán Euclid.

## Examples

```python
gcd(84, 30) -> 6
gcd(84, -30) -> 6
gcd(0, 7) -> 7
```

---

# `extended_gcd(a, b)`

## Input

| Tham số | Kiểu dữ liệu | Ý nghĩa            |
| ------- | ------------ | ------------------ |
| `a`     | `int`        | Số nguyên thứ nhất |
| `b`     | `int`        | Số nguyên thứ hai  |

---

## Output

Trả về:

```python
tuple[int, int, int]
```

Dạng:

```python
(g, x, y)
```

Thoả mãn:

```python
x*a + y*b = g
```

Trong đó:

- `g` là `gcd(a, b)`
- `x` và `y` là hệ số Bézout

---

## Mô tả

Cài đặt thuật toán Euclid mở rộng để:

- Tìm `gcd(a, b)`
- Tìm hai hệ số `x`, `y` thoả mãn:

```python
x*a + y*b = gcd(a, b)
```

---

## Examples

```python
extended_gcd(67, 12) -> (1, -5, 28)
```

Vì:

```python
-5*67 + 28*12 = 1
```

---

# `mod_inverse(a, n)`

## Input

| Tham số | Kiểu dữ liệu | Ý nghĩa                      |
| ------- | ------------ | ---------------------------- |
| `a`     | `int`        | Số cần tìm nghịch đảo modulo |
| `n`     | `int`        | Giá trị modulo               |

---

## Output

Trả về:

```python
int
```

Giá trị `x` thoả mãn:

```python
a*x ≡ 1 (mod n)
```

---

## Mô tả

Tìm nghịch đảo modulo của `a` theo modulo `n`.
Nghịch đảo modulo chỉ tồn tại khi:

```python
gcd(a, n) = 1
```

---

## Exceptions

```python
ValueError
```

Xuất hiện khi:

```python
gcd(a, n) != 1
```

---

## Examples

```python
mod_inverse(3, 11) -> 4
```

Vì:

```python
3*4 ≡ 1 (mod 11)
```

---

# `is_coprime(a, b)`

## Input

| Tham số | Kiểu dữ liệu | Ý nghĩa            |
| ------- | ------------ | ------------------ |
| `a`     | `int`        | Số nguyên thứ nhất |
| `b`     | `int`        | Số nguyên thứ hai  |

---

## Output

Trả về:

```python
bool
```

- `True` nếu `a` và `b` nguyên tố cùng nhau
- `False` nếu không nguyên tố cùng nhau

---

## Mô tả

Kiểm tra hai số nguyên có nguyên tố cùng nhau hay không.
Hai số được gọi là nguyên tố cùng nhau nếu:

```python
gcd(a, b) = 1
```

---

## Examples

```python
is_coprime(8, 15) -> True
is_coprime(12, 18) -> False
```

---

# rsa_core.py

# `generate_prime(bits)`

## Input

| Tham số | Kiểu dữ liệu | Ý nghĩa                           |
| ------- | ------------ | --------------------------------- |
| `bits`  | `int`        | Số bit mong muốn của số nguyên tố |

---

## Output

Trả về:

```python
int
```

Trong đó giá trị trả về là:

- Một số nguyên tố có độ dài xấp xỉ `bits` bit

---

## Mô tả

## Sinh ngẫu nhiên một số nguyên tố phục vụ cho RSA demo bằng `sympy.randprime`.

## Exceptions

```python
ValueError
```

Xuất hiện khi:

```python
bits < 4
```

---

## Examples

```python
generate_prime(8) -> 197
```

---

# `generate_shared_modulus(bits)`

## Input

| Tham số | Kiểu dữ liệu | Ý nghĩa                      |
| ------- | ------------ | ---------------------------- |
| `bits`  | `int`        | Độ dài mong muốn của modulus |

---

## Output

Trả về:

```python
dict[str, int]
```

Dạng:

```python
{
    "p": p,
    "q": q,
    "n": n,
    "phi": phi
}
```

---

## Mô tả

Sinh hai số nguyên tố `p`, `q` và tính:

```python
n = p*q
phi = (p-1)*(q-1)
```

## Modulus `n` này sẽ được dùng chung cho nhiều public key trong Common Modulus Attack.

## Exceptions

```python
ValueError
```

Xuất hiện khi:

```python
bits < 16
```

---

## Examples

```python
generate_shared_modulus(32)
```

---

# `choose_public_exponent(phi, avoid=None, coprime_with=None)`

## Input

| Tham số        | Kiểu dữ liệu       | Ý nghĩa                                               |
| -------------- | ------------------ | ----------------------------------------------------- |
| `phi`          | `int`              | Giá trị phi(n)                                        |
| `avoid`        | `set[int] \| None` | Tập các e không muốn chọn                             |
| `coprime_with` | `set[int] \| None` | Tập các e mà e mới phải nguyên tố cùng nhau với chúng |

---

## Output

Trả về:

```python
int
```

Trong đó giá trị trả về là:

- Public exponent `e` hợp lệ cho RSA

---

## Mô tả

Chọn số mũ công khai `e` thoả:

```python
1 < e < phi
gcd(e, phi) = 1
```

Nếu dùng cho Common Modulus Attack:

```python
gcd(e1, e2) = 1
```

---

## Exceptions

```python
ValueError
```

Xuất hiện khi:

```python
phi <= 3
```

## hoặc không tìm được `e` hợp lệ.

## Examples

```python
choose_public_exponent(3120) -> 65537
```

---

# `generate_rsa_key_with_shared_n(n, phi, e)`

## Input

| Tham số | Kiểu dữ liệu | Ý nghĩa         |
| ------- | ------------ | --------------- |
| `n`     | `int`        | Modulus RSA     |
| `phi`   | `int`        | Giá trị phi(n)  |
| `e`     | `int`        | Public exponent |

---

## Output

Trả về:

```python
dict[str, int | tuple[int, int]]
```

Dạng:

```python
{
    "n": n,
    "e": e,
    "d": d,
    "public_key": (n, e),
    "private_key": (n, d)
}
```

---

## Mô tả

Tạo một cặp khóa RSA từ modulus `n` đã có sẵn.
Tính:

```python
d = e^(-1) mod phi
```

---

## Exceptions

```python
ValueError
```

Xuất hiện khi:

- `n <= 0`
- `phi <= 0`
- `e` không thoả:

```python
1 < e < phi
```

- hoặc:

```python
gcd(e, phi) != 1
```

---

## Examples

```python
generate_rsa_key_with_shared_n(n, phi, e)
```

---

# `rsa_encrypt_int(m, e, n)`

## Input

| Tham số | Kiểu dữ liệu | Ý nghĩa               |
| ------- | ------------ | --------------------- |
| `m`     | `int`        | Bản rõ dạng số nguyên |
| `e`     | `int`        | Public exponent       |
| `n`     | `int`        | Modulus RSA           |

---

## Output

Trả về:

```python
int
```

Trong đó giá trị trả về là:

- Bản mã `c`

---

## Mô tả

Mã hóa RSA theo công thức:

```python
c = m^e mod n
```

---

## Exceptions

```python
ValueError
```

Xuất hiện khi:

```python
0 <= m < n
```

## không thoả mãn.

## Examples

```python
rsa_encrypt_int(12, e, n)
```

---

# `rsa_decrypt_int(c, d, n)`

## Input

| Tham số | Kiểu dữ liệu | Ý nghĩa               |
| ------- | ------------ | --------------------- |
| `c`     | `int`        | Bản mã dạng số nguyên |
| `d`     | `int`        | Private exponent      |
| `n`     | `int`        | Modulus RSA           |

---

## Output

Trả về:

```python
int
```

Trong đó giá trị trả về là:

- Bản rõ `m`

---

## Mô tả

Giải mã RSA theo công thức:

```python
m = c^d mod n
```

---

## Exceptions

```python
ValueError
```

Xuất hiện khi:

```python
0 <= c < n
```

## không thoả mãn.

## Examples

```python
rsa_decrypt_int(c, d, n)
```

---

# `generate_two_keys_with_shared_n(bits)`

## Input

| Tham số | Kiểu dữ liệu | Ý nghĩa                      |
| ------- | ------------ | ---------------------------- |
| `bits`  | `int`        | Độ dài mong muốn của modulus |

---

## Output

Trả về:

```python
dict
```

Chứa:

```python
{
    "modulus_info": modulus_info,
    "key1": key1,
    "key2": key2
}
```

---

## Mô tả

Sinh hai cặp khóa RSA cùng sử dụng một modulus `n`:

```python
key1 = (n, e1)
key2 = (n, e2)
```

Trong đó:

```python
gcd(e1, e2) = 1
```

## Phục vụ demo Common Modulus Attack.

## Examples

```python
generate_two_keys_with_shared_n(32)
```

---

# common_modulus_attack.py

# `validate_attack_inputs_pp2(c1, c2, e1, e2, n)`

## Input

| Tham số | Kiểu dữ liệu | Ý nghĩa                  |
| ------- | ------------ | ------------------------ |
| `c1`    | `int`        | Bản mã thứ nhất          |
| `c2`    | `int`        | Bản mã thứ hai           |
| `e1`    | `int`        | Public exponent thứ nhất |
| `e2`    | `int`        | Public exponent thứ hai  |
| `n`     | `int`        | Modulus RSA dùng chung   |

---

## Output

Trả về:

```python
None
```

---

## Mô tả

## Kiểm tra dữ liệu đầu vào cho Common Modulus Attack PP2.

## Exceptions

```python
ValueError
```

Xuất hiện khi:

- `n <= 1`
- `e1 <= 1`
- `e2 <= 1`
- `e1 == e2`
- `c1` không thỏa `0 <= c1 < n`
- `c2` không thỏa `0 <= c2 < n`

---

# `validate_attack_inputs_pp1(ciphertext, victim_e, attacker_e, attacker_d, n)`

## Input

| Tham số      | Kiểu dữ liệu | Ý nghĩa                          |
| ------------ | ------------ | -------------------------------- |
| `ciphertext` | `int`        | Bản mã cần giải                  |
| `victim_e`   | `int`        | Public exponent của nạn nhân     |
| `attacker_e` | `int`        | Public exponent của kẻ tấn công  |
| `attacker_d` | `int`        | Private exponent của kẻ tấn công |
| `n`          | `int`        | Modulus RSA dùng chung           |

---

## Output

Trả về:

```python
None
```

---

## Mô tả

## Kiểm tra dữ liệu đầu vào cho Common Modulus Attack PP1.

## Exceptions

```python
ValueError
```

Xuất hiện khi:

- `n <= 1`
- `victim_e <= 1`
- `attacker_e <= 1`
- `attacker_d <= 1`
- `victim_e == attacker_e`
- `ciphertext` không thỏa `0 <= ciphertext < n`

---

# `handle_negative_power(c, exponent, n)`

## Input

| Tham số    | Kiểu dữ liệu | Ý nghĩa                         |
| ---------- | ------------ | ------------------------------- |
| `c`        | `int`        | Cơ số, thường là `c1` hoặc `c2` |
| `exponent` | `int`        | Số mũ Bézout, có thể âm         |
| `n`        | `int`        | Modulus RSA                     |

---

## Output

Trả về:

```python
int
```

Trong đó giá trị trả về là:

- Giá trị `c^exponent mod n`

---

## Mô tả

Tính lũy thừa modulo kể cả khi số mũ âm.
Nếu `exponent >= 0`:

```python
c^exponent mod n
```

Nếu `exponent < 0`:

```python
(c^-1)^abs(exponent) mod n
```

---

## Exceptions

```python
ValueError
```

Xuất hiện khi:

- `n <= 1`
- `c` không thỏa `0 <= c < n`
- cần nghịch đảo modulo nhưng `c` không có inverse modulo `n`

---

# `compute_signed_power_with_trace(c, exponent, n, label)`

## Input

| Tham số    | Kiểu dữ liệu | Ý nghĩa                         |
| ---------- | ------------ | ------------------------------- |
| `c`        | `int`        | Bản mã `c1` hoặc `c2`           |
| `exponent` | `int`        | Số mũ Bézout tương ứng          |
| `n`        | `int`        | Modulus RSA                     |
| `label`    | `str`        | Nhãn để ghi trace, ví dụ `"C1"` |

---

## Output

Trả về:

```python
tuple[int, dict[str, int | str | bool]]
```

Dạng:

```python
(result, trace)
```

Trong đó:

- `result` là giá trị `c^exponent mod n`
- `trace` là dictionary mô tả cách tính

---

## Mô tả

Tính `c^exponent mod n` và lưu lại các bước trung gian để hiển thị.
Nếu `exponent` âm thì dùng nghịch đảo modulo của `c`.

---

# `common_modulus_attack_pp1(ciphertext, victim_e, attacker_e, attacker_d, n)`

## Input

| Tham số      | Kiểu dữ liệu | Ý nghĩa                          |
| ------------ | ------------ | -------------------------------- |
| `ciphertext` | `int`        | Bản mã cần giải                  |
| `victim_e`   | `int`        | Public exponent của nạn nhân     |
| `attacker_e` | `int`        | Public exponent của kẻ tấn công  |
| `attacker_d` | `int`        | Private exponent của kẻ tấn công |
| `n`          | `int`        | Modulus RSA dùng chung           |

---

## Output

Trả về:

```python
tuple[int, int, dict[str, int | str | list[dict[str, int]]]]
```

Dạng:

```python
(recovered_victim_d, recovered_m, trace)
```

Trong đó:

- `recovered_victim_d` là private exponent hợp lệ tìm được cho victim
- `recovered_m` là bản rõ dạng số nguyên khôi phục được
- `trace` là dictionary chứa các bước trung gian

---

## Mô tả

Thực hiện Common Modulus Attack PP1.
Kẻ tấn công dùng public key và private key của chính mình để tìm private exponent hợp lệ cho nạn nhân.
Đầu tiên tính:

```python
t = attacker_e * attacker_d - 1
```

## Sau đó tìm hệ số Bézout để suy ra private exponent của victim.

## Exceptions

```python
ValueError
```

Xuất hiện khi:

- input không hợp lệ
- `t <= 0`
- không tìm được private exponent cho victim

---

# `common_modulus_attack_pp2(c1, c2, e1, e2, n)`

## Input

| Tham số | Kiểu dữ liệu | Ý nghĩa                  |
| ------- | ------------ | ------------------------ |
| `c1`    | `int`        | Bản mã thứ nhất          |
| `c2`    | `int`        | Bản mã thứ hai           |
| `e1`    | `int`        | Public exponent thứ nhất |
| `e2`    | `int`        | Public exponent thứ hai  |
| `n`     | `int`        | Modulus RSA dùng chung   |

---

## Output

Trả về:

```python
tuple[int, dict[str, int | str | bool | dict]]
```

Dạng:

```python
(recovered_m, trace)
```

Trong đó:

- `recovered_m` là bản rõ dạng số nguyên đã khôi phục
- `trace` là dictionary chứa các bước trung gian

---

## Mô tả

Thực hiện Common Modulus Attack PP2.
Kịch bản:

```python
c1 = m^e1 mod n
c2 = m^e2 mod n
gcd(e1, e2) = 1
```

Dùng Extended Euclidean Algorithm để tìm `a`, `b` sao cho:

```python
a*e1 + b*e2 = 1
```

Sau đó khôi phục bản rõ:

```python
M = C1^a * C2^b mod n
```

## Nếu `a` hoặc `b` âm thì dùng nghịch đảo modulo.

## Exceptions

```python
ValueError
```

Xuất hiện khi:

- input không hợp lệ
- `gcd(e1, e2) != 1`
- Extended GCD không trả về `gcd = 1`

---

# `common_modulus_attack`

## Input

| Tham số | Kiểu dữ liệu | Ý nghĩa                  |
| ------- | ------------ | ------------------------ |
| `c1`    | `int`        | Bản mã thứ nhất          |
| `c2`    | `int`        | Bản mã thứ hai           |
| `e1`    | `int`        | Public exponent thứ nhất |
| `e2`    | `int`        | Public exponent thứ hai  |
| `n`     | `int`        | Modulus RSA dùng chung   |

---

## Output

Trả về:

```python
tuple[int, dict[str, int | str | bool | dict]]
```

Dạng:

```python
(recovered_m, trace)
```

---

## Mô tả

Tên rút gọn trỏ tới hàm:

```python
common_modulus_attack_pp2
```

## Dùng để gọi nhanh kỹ thuật Common Modulus Attack PP2.
