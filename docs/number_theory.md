# Phân tích file `number_theory.py`

## 1. Vai trò của file

File `number_theory.py` chứa các hàm toán học nền tảng được sử dụng trong chương trình RSA Common Modulus Attack Demo.

Các hàm trong file này không trực tiếp mã hóa, giải mã hay tấn công RSA. Thay vào đó, chúng cung cấp các phép toán số học cần thiết cho các file khác như:

- `rsa_core.py`: dùng để kiểm tra số mũ công khai `e` có hợp lệ không và tính khóa bí mật `d`.
- `common_modulus_attack.py`: dùng để tìm hệ số Bézout, kiểm tra điều kiện nguyên tố cùng nhau và xử lý nghịch đảo modulo.

Các hàm chính gồm:

| Hàm                  | Chức năng chính                              |
| -------------------- | -------------------------------------------- |
| `gcd(a, b)`          | Tính ước chung lớn nhất của hai số nguyên    |
| `extended_gcd(a, b)` | Tính GCD và tìm hệ số Bézout                 |
| `mod_inverse(a, n)`  | Tính nghịch đảo modulo                       |
| `is_coprime(a, b)`   | Kiểm tra hai số có nguyên tố cùng nhau không |

