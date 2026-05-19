# Phân tích file `file_codec.py`

## 1. Vai trò của file

File `file_codec.py` chứa các hàm chuyển đổi dữ liệu giữa nhiều dạng khác nhau:

- `bytes` sang `int`
- `int` sang `bytes`
- `text` sang `int`
- `int` sang `text`
- `file` sang `bytes`
- `bytes` sang `file`
- `file` sang `int`
- `int` sang `file`

Lý do cần file này là vì RSA trong chương trình demo chỉ xử lý trực tiếp bản rõ dạng số nguyên.

Người dùng thường nhập dữ liệu ở dạng text hoặc file, ví dụ:

```text
HELLO PTIT
```
