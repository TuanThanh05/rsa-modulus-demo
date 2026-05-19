# Phân tích file `common_modulus_attack.py`

## 1. Vai trò của file

File `common_modulus_attack.py` chứa các hàm thực hiện RSA Common Modulus Attack.

Đây là file quan trọng nhất của đề tài vì trực tiếp cài đặt logic tấn công module chung trong RSA.

File này xử lý hai phương pháp:

| Phương pháp | Mục tiêu                               | Ý tưởng chính                                                                 |
| ----------- | -------------------------------------- | ----------------------------------------------------------------------------- |
| PP1         | Tìm khóa bí mật tương đương của victim | Dùng `attacker_e`, `attacker_d` để suy ra private exponent của victim         |
| PP2         | Khôi phục bản rõ `M`                   | Dùng hai bản mã `C1`, `C2` của cùng bản rõ, cùng modulus `n`, khác `e1`, `e2` |

Trong PP2, điều kiện quan trọng là:

```text
gcd(e1, e2) = 1
```
