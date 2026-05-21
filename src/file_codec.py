"""
file_codec.py

Các hàm chuyển đổi dữ liệu giữa bytes/text/file và số nguyên.

Mục đích:
- RSA chỉ mã hóa được số nguyên m.
- Người dùng thường nhập text hoặc file.
- File này giúp chuyển:
    bytes -> int
    int -> bytes
    text -> int
    int -> text
    file -> int
    int -> file

Lưu ý:
Đây là phần phục vụ demo textbook RSA.
Khi dùng RSA, bản rõ dạng số nguyên m phải thỏa:
    0 <= m < n
"""

from pathlib import Path


def bytes_to_int(data: bytes) -> int:
    if not isinstance(data, bytes):
        raise TypeError("data phải có kiểu bytes")

    if data == b"":
        return 0

    value = int.from_bytes(data, byteorder="big")

    return value


def int_to_bytes(value: int, length: int | None = None) -> bytes:
    if not isinstance(value, int):
        raise TypeError("value phải có kiểu int")

    if value < 0:
        raise ValueError("value phải là số nguyên không âm")

    if length is not None:
        if not isinstance(length, int):
            raise TypeError("length phải có kiểu int hoặc None")

        if length < 0:
            raise ValueError("length phải là số nguyên không âm")

    if value == 0:
        if length is None:
            return b""

        return bytes(length)

    minimum_length = (value.bit_length() + 7) // 8

    if length is None:
        length = minimum_length

    if length < minimum_length:
        raise ValueError("length không đủ để biểu diễn value")

    data = value.to_bytes(length, byteorder="big")

    return data


def text_to_int(text: str, encoding: str = "utf-8") -> int:
    if not isinstance(text, str):
        raise TypeError("text phải có kiểu str")

    if not isinstance(encoding, str):
        raise TypeError("encoding phải có kiểu str")

    text_bytes = text.encode(encoding)
    value = bytes_to_int(text_bytes)

    return value


def int_to_text(value: int, encoding: str = "utf-8") -> str:
    if not isinstance(encoding, str):
        raise TypeError("encoding phải có kiểu str")

    text_bytes = int_to_bytes(value)
    text = text_bytes.decode(encoding)

    return text


def read_file_as_bytes(path: str | Path) -> bytes:
    file_path = Path(path)

    with open(file_path, "rb") as file:
        data = file.read()

    return data


def write_bytes_to_file(data: bytes, path: str | Path) -> None:
    if not isinstance(data, bytes):
        raise TypeError("data phải có kiểu bytes")

    file_path = Path(path)

    if file_path.parent != Path("."):
        file_path.parent.mkdir(parents=True, exist_ok=True)

    with open(file_path, "wb") as file:
        file.write(data)


def read_file_as_int(path: str | Path) -> int:
    data = read_file_as_bytes(path)
    value = bytes_to_int(data)

    return value


def write_int_to_file(
    value: int,
    path: str | Path,
    length: int | None = None,
) -> None:
    data = int_to_bytes(value, length)
    write_bytes_to_file(data, path)


def get_byte_length_from_int(value: int) -> int:
    if not isinstance(value, int):
        raise TypeError("value phải có kiểu int")

    if value < 0:
        raise ValueError("value phải là số nguyên không âm")

    if value == 0:
        return 0

    byte_length = (value.bit_length() + 7) // 8

    return byte_length


def ensure_message_fits_modulus(message_int: int, n: int) -> None:
    if not isinstance(message_int, int):
        raise TypeError("message_int phải có kiểu int")

    if not isinstance(n, int):
        raise TypeError("n phải có kiểu int")

    if n <= 1:
        raise ValueError("n phải là số nguyên lớn hơn 1")

    if not (0 <= message_int < n):
        raise ValueError(
            "Bản rõ dạng số nguyên phải thỏa 0 <= message_int < n. "
            "Hãy dùng message ngắn hơn hoặc sinh modulus n lớn hơn."
        )
