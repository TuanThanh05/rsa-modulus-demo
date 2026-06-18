# RSA Common Modulus Attack Demo

Chương trình minh họa kỹ thuật **RSA Common Modulus Attack** trên mô hình textbook RSA, được phát triển bởi **Nhóm 4** của nhóm mã số **065, 063, 062, 055, 004**.

Project tập trung vào kịch bản nhiều khóa RSA cùng dùng chung một modulus `N` nhưng có public exponent khác nhau. Khi cùng một bản rõ `M` được mã hóa thành hai bản mã `C1`, `C2` với cùng `N` và `gcd(e1, e2) = 1`, attacker có thể dùng **Extended Euclidean Algorithm** để khôi phục lại `M` mà không cần biết private key.

> [!WARNING]
> Project chỉ phục vụ mục đích học tập và minh họa textbook RSA. Không sử dụng mã nguồn này cho hệ thống bảo mật thực tế.

## Tổng quan

Project này giúp minh họa rõ ràng:

- Cách sinh khóa RSA cơ bản.
- Vì sao việc dùng chung modulus `N` là nguy hiểm.
- Cách mã hóa cùng một bản rõ với hai public exponent khác nhau.
- Cách dùng hệ số Bézout để khôi phục bản rõ.
- Cách hiển thị lại toàn bộ quá trình tính toán trên CLI bằng `rich`.

## Ý tưởng tấn công PP2

Giả sử cùng một bản rõ `M` được mã hóa bằng hai public key khác nhau nhưng dùng chung modulus `N`:

```text
C1 = M^e1 mod N
C2 = M^e2 mod N
```

Nếu:

```text
gcd(e1, e2) = 1
```

thì tồn tại hai số nguyên `a`, `b` sao cho:

```text
a * e1 + b * e2 = 1
```

Từ đó:

```text
C1^a * C2^b
= (M^e1)^a * (M^e2)^b
= M^(a*e1 + b*e2)
= M^1
= M mod N
```

Vì vậy có thể khôi phục bản rõ theo công thức:

```text
M = C1^a * C2^b mod N
```

Nếu `a` hoặc `b` âm, chương trình sẽ xử lý bằng nghịch đảo modulo trước khi lũy thừa.

## Tính năng chính

- Mã hóa RSA
- Giải mã RSA
- Chạy chế độ thủ công khi đã có sẵn `N`, `e1`, `e2`, `C1`, `C2`.
- Khôi phục bản rõ bằng phương pháp modulus số chung

## Công nghệ sử dụng

|      Thành phần     |                    Vai trò                    |
| ------------------- | --------------------------------------------- |
| `Python`            | Ngôn ngữ chính của project                    |
| `sympy`             | Hỗ trợ sinh số nguyên tố                      |
| `customtkinter`     | Hiển thị giao diện trực quan rõ ràng          |

## Cấu trúc project

```text
rsa-modulus-demo/
├── README.md
├── requirements.txt
└── src/
    ├── main.py
    ├── Attack_rsa_core/
    │   └── common_modulus_attack.py
    ├── Display/
    │   ├── __init__.py
    │   ├── attackui.py
    │   └── cipherui.py
    ├── File_code/
    │   └── file_codec.py
    ├── Number_theory/
    │   └── number_theory.py
    ├── Rsa_core/
    │   └── rsa_core.py
    └── Validate/
        └── validate_attack.py
```

## Vai trò từng file

| File                                           | Vai trò                                                            |
| ---------------------------------------------- | ------------------------------------------------------------------ |
| `src/main.py`                                  | File chạy chính, khởi tạo giao diện Attack và Cipher               |
| `src/Attack_rsa_core/common_modulus_attack.py` | Thuật toán tấn công Common Modulus và khôi phục bản rõ             |
| `src/Display/attackui.py`                      | Giao diện tab Attack, nhập C1, C2, e1, e2, n và hiển thị kết quả   |
| `src/Display/cipherui.py`                      | Giao diện tab Cipher, mã hóa/giải mã và sinh thông tin RSA         |
| `src/Display/__init__.py`                      | Đánh dấu thư mục `Display` là package Python                       |
| `src/File_code/file_codec.py`                  | Chuyển đổi giữa text, bytes, các hệ số và số nguyên                |
| `src/Number_theory/number_theory.py`           | `gcd`, `extended_gcd`, `mod_inverse`, kiểm tra nguyên tố cùng nhau |
| `src/Rsa_core/rsa_core.py`                     | Các hàm RSA cốt lõi: sinh khóa, chọn e, mã hóa, giải mã            |
| `src/Validate/validate_attack.py`              | Kiểm tra dữ liệu đầu vào cho thuật toán tấn công                   |                                |

## Cài đặt môi trường

### 1. Tạo môi trường ảo

```powershell
python -m venv .venv
```

Kích hoạt trên PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

Kích hoạt trên Git Bash:

```bash
source .venv/Scripts/activate
```

Kích hoạt trên Linux/macOS:

```bash
source .venv/bin/activate
```

### 2. Cài dependencies

```bash
pip install -r requirements.txt
```

## Chạy nhanh

Lệnh đơn giản nhất để chạy:

```bash
cd src

python main.py
```
## Kết luận

Project mô phỏng rõ quá trình tấn công **RSA Common Modulus Attack PP2**: sinh dữ liệu, mã hóa cùng một bản rõ dưới hai public exponent khác nhau, tìm hệ số Bézout và khôi phục lại bản rõ bằng Extended Euclidean Algorithm.

Điểm quan trọng rút ra là: **không được tái sử dụng modulus `N` giữa nhiều khóa RSA**. Trong thực tế, mỗi cặp khóa RSA phải được sinh độc lập với cặp số nguyên tố riêng.

## Lời cảm ơn

Nhóm 4 chân thành cảm ơn sự góp ý và hỗ trợ từ các bạn đã xem.
