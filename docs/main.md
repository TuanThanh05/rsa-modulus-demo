# Phân tích file `main.py`

## 1. Vai trò của file

File `main.py` là điểm chạy chính của project RSA Common Modulus Attack Demo.

File này có nhiệm vụ điều phối toàn bộ chương trình từ lúc người dùng nhập lệnh trên terminal cho đến khi chương trình hiển thị kết quả cuối cùng.

File `main.py` không trực tiếp cài đặt thuật toán toán học hoặc thuật toán tấn công. Thay vào đó, nó gọi các hàm từ những file khác:

| File                       | Vai trò được `main.py` sử dụng           |
| -------------------------- | ---------------------------------------- |
| `rsa_core.py`              | Sinh khóa RSA, mã hóa bản rõ             |
| `common_modulus_attack.py` | Thực hiện PP1 và PP2                     |
| `file_codec.py`            | Chuyển đổi text/file/bytes/int           |
| `display.py`               | Hiển thị kết quả ra terminal bằng `rich` |

Nói ngắn gọn, `main.py` là file điều khiển luồng:

```text
Input từ CLI
    |
    v
Xử lý dữ liệu đầu vào
    |
    v
Gọi hàm RSA hoặc hàm tấn công
    |
    v
Hiển thị trace và kết quả
    |
    v
Lưu JSON hoặc output file nếu người dùng yêu cầu
```
