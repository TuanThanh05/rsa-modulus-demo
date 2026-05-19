# Phân tích file `rsa_core.py`

## 1. Vai trò của file

File `rsa_core.py` chứa các hàm cốt lõi để xây dựng hệ RSA phục vụ demo Common Modulus Attack.

File này không trực tiếp thực hiện tấn công. Nhiệm vụ chính của file là tạo ra môi trường RSA hợp lệ để các file khác có thể sử dụng, đặc biệt là:

- Sinh hai số nguyên tố `p`, `q`.
- Tính modulus chung `n = p * q`.
- Tính `phi(n) = (p - 1) * (q - 1)`.
- Chọn public exponent `e`.
- Tính private exponent `d`.
- Mã hóa bản rõ dạng số nguyên.
- Giải mã bản mã dạng số nguyên.
- Tạo hai cặp khóa RSA dùng chung cùng một modulus `n`.

Trong đề tài Common Modulus Attack, file này đặc biệt quan trọng vì nó tạo ra kịch bản có chủ đích:

```text