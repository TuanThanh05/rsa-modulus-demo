# Phân tích file `display.py`

## 1. Vai trò của file

File `display.py` chứa các hàm hiển thị dữ liệu demo RSA Common Modulus Attack ra terminal.

File này không thực hiện tính toán mật mã. Cụ thể, file này không:

- Sinh số nguyên tố.
- Tạo khóa RSA.
- Mã hóa RSA.
- Giải mã RSA.
- Thực hiện Common Modulus Attack.

File này chỉ nhận dữ liệu đã được tính toán từ các file khác như:

- `rsa_core.py`
- `common_modulus_attack.py`
- `file_codec.py`
- `main.py`

Sau đó in dữ liệu ra màn hình theo dạng bảng, tiêu đề, kết quả và trace từng bước.

Mục tiêu chính của file là làm cho chương trình demo dễ nhìn hơn khi chạy trên CLI.

---

## 2. Thư viện được sử dụng

File sử dụng thư viện `rich`:

```python
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
```
