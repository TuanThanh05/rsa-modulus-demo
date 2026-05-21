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

- Demo tự động toàn bộ Common Modulus Attack PP2.
- Chạy chế độ thủ công khi đã có sẵn `N`, `e1`, `e2`, `C1`, `C2`.
- Hỗ trợ đầu vào dạng text hoặc file.
- Có thể lưu trace ra JSON.
- Có thể ghi dữ liệu khôi phục ra file.
- Có thêm công cụ `src.rsa` để kiểm thử RSA cơ bản độc lập với bài toán tấn công.

## Công nghệ sử dụng

| Thành phần | Vai trò                                       |
| ---------- | --------------------------------------------- |
| `Python`   | Ngôn ngữ chính của project                    |
| `sympy`    | Hỗ trợ sinh số nguyên tố                      |
| `rich`     | Hiển thị bảng, panel, công thức trên terminal |
| `argparse` | Xử lý tham số dòng lệnh                       |
| `json`     | Lưu trace và dữ liệu demo                     |

## Cấu trúc project

```text
rsa-modulus-demo/
├── README.md
├── requirements.txt
└── src/
    ├── __init__.py
    ├── common_modulus_attack.py
    ├── display.py
    ├── file_codec.py
    ├── main.py
    ├── number_theory.py
    ├── rsa.py
    └── rsa_core.py
```

## Vai trò từng file

| File                           | Vai trò                                                            |
| ------------------------------ | ------------------------------------------------------------------ |
| `src/main.py`                  | CLI chính cho Common Modulus Attack PP2                            |
| `src/common_modulus_attack.py` | Thuật toán tấn công và khôi phục bản rõ                            |
| `src/rsa_core.py`              | Các hàm RSA cốt lõi: sinh khóa, mã hóa, giải mã                    |
| `src/number_theory.py`         | `gcd`, `extended_gcd`, `mod_inverse`, kiểm tra nguyên tố cùng nhau |
| `src/file_codec.py`            | Chuyển đổi giữa text, bytes, file và số nguyên                     |
| `src/display.py`               | Hiển thị trace, bảng, công thức trên terminal                      |
| `src/rsa.py`                   | Công cụ kiểm thử RSA cơ bản riêng                                  |

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

Lệnh đơn giản nhất để chạy demo tự động:

```bash
python -m src.main auto
```

## CLI chính: `src.main`

Lệnh gốc:

```bash
python -m src.main <command> [options]
```

Các command hiện có:

| Command      | Ý nghĩa               |
| ------------ | --------------------- |
| `auto`       | Chạy demo PP2 tự động |
| `demo`       | Alias của `auto`      |
| `demo-pp2`   | Alias của `auto`      |
| `manual`     | Chạy PP2 thủ công     |
| `attack`     | Alias của `manual`    |
| `attack-pp2` | Alias của `manual`    |

### Demo tự động PP2

Chạy với bản rõ mặc định:

```bash
python -m src.main auto
```

Chạy với bản rõ tự nhập:

```bash
python -m src.main auto --message "NOI DUNG BAN RO"
```

Chạy với modulus lớn hơn:

```bash
python -m src.main auto --message "NOI DUNG BAN RO" --bits 1024
```

Dùng alias:

```bash
python -m src.main demo --message "NOI DUNG BAN RO" --bits 512
python -m src.main demo-pp2 --message "NOI DUNG BAN RO" --bits 512
```

### Demo với file đầu vào

```bash
python -m src.main auto --file input.bin --bits 1024
```

Ghi dữ liệu khôi phục ra file:

```bash
python -m src.main auto --file input.bin --bits 1024 --output-file recovered.bin
```

Lưu bộ dữ liệu demo ra JSON:

```bash
python -m src.main auto --message "HELLO PTIT" --bits 512 --save-json trace.json
```

### Chạy thủ công PP2

Khi đã có sẵn `N`, `e1`, `e2`, `C1`, `C2`:

```bash
python -m src.main attack-pp2 --n <N> --e1 <e1> --e2 <e2> --c1 <C1> --c2 <C2>
```

Hoặc dùng alias:

```bash
python -m src.main manual --n <N> --e1 <e1> --e2 <e2> --c1 <C1> --c2 <C2>
python -m src.main attack --n <N> --e1 <e1> --e2 <e2> --c1 <C1> --c2 <C2>
```

Một số tùy chọn hữu ích ở chế độ thủ công:

- `--decode-text`: thử decode kết quả về UTF-8.
- `--no-decode-text`: không decode kết quả.
- `--output-file`: ghi recovered message ra file bytes.
- `--output-length`: chỉ định số byte khi ghi file.
- `--save-json`: lưu trace tấn công ra JSON.

## Công cụ RSA cơ bản: `src.rsa`

File `src.rsa` dùng để kiểm thử RSA cơ bản ngoài bài toán Common Modulus Attack.

Lệnh gốc:

```bash
python -m src.rsa <command> [options]
```

Các command:

| Command  | Ý nghĩa                                 |
| -------- | --------------------------------------- |
| `auto`   | Tự sinh khóa RSA, mã hóa và giải mã     |
| `manual` | Nhập khóa thủ công để mã hóa và giải mã |

### Ví dụ nhanh

Chạy tự động:

```bash
python -m src.rsa auto --message "NOI DUNG TIN NHAN" --bits 512
```

Chạy tự động với `e` tự chọn:

```bash
python -m src.rsa auto --message "NOI DUNG TIN NHAN" --bits 512 --e 65537
```

Chạy với file:

```bash
python -m src.rsa auto --file input.bin --bits 1024
```

Chạy thủ công với `p`, `q`, `e`:

```bash
python -m src.rsa manual --p <p> --q <q> --e <e> --m <m>
```

Chạy thủ công khi đã có `N`, `e`, `d`:

```bash
python -m src.rsa manual --n <n> --e <e> --d <d> --m <m>
```

Giải mã một ciphertext có sẵn:

```bash
python -m src.rsa manual --n <n> --e <e> --d <d> --ciphertext <C>
```

## Ghi chú khi nhập dữ liệu

- `src.main` hỗ trợ `--message` hoặc `--file` trong chế độ demo tự động.
- `src.rsa` hỗ trợ `--message`, `--file`, hoặc `--m`.
- Một số tham số số nguyên có thể nhập ở dạng thập phân, hex (`0x...`) hoặc nhị phân (`0b...`).
- Nếu dùng file đầu vào, dữ liệu phải đủ nhỏ để thỏa điều kiện `0 <= M < N`.
- Các bit có thể thay đổi được

## Kết luận

Project mô phỏng rõ quá trình tấn công **RSA Common Modulus Attack PP2**: sinh dữ liệu, mã hóa cùng một bản rõ dưới hai public exponent khác nhau, tìm hệ số Bézout và khôi phục lại bản rõ bằng Extended Euclidean Algorithm.

Điểm quan trọng rút ra là: **không được tái sử dụng modulus `N` giữa nhiều khóa RSA**. Trong thực tế, mỗi cặp khóa RSA phải được sinh độc lập với cặp số nguyên tố riêng.

## Lời cảm ơn

Nhóm 4 chân thành cảm ơn sự góp ý và hỗ trợ từ các bạn đã xem.
