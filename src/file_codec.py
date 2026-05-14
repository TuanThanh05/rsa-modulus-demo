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
    """
    Chuyển dữ liệu bytes thành số nguyên.

    Args:
        data: Dữ liệu dạng bytes.

    Returns:
        int: Số nguyên biểu diễn dữ liệu bytes.

    Example:
        bytes_to_int(b"ABC") -> 4276803
    """
    if not isinstance(data, bytes):
        raise TypeError("data phải có kiểu bytes")

    if data == b"":
        return 0

    value = int.from_bytes(data, byteorder="big")

    return value


def int_to_bytes(value: int, length: int | None = None) -> bytes:
    """
    Chuyển số nguyên thành dữ liệu bytes.

    Args:
        value: Số nguyên cần chuyển.
        length: Số byte mong muốn của kết quả.
            Nếu length = None, hàm tự tính số byte tối thiểu.

    Returns:
        bytes: Dữ liệu bytes khôi phục từ số nguyên.

    Raises:
        TypeError: Nếu value hoặc length sai kiểu.
        ValueError: Nếu value âm hoặc length không đủ.

    Example:
        int_to_bytes(4276803) -> b"ABC"

    Ghi chú:
        Nếu dữ liệu gốc có byte 0 ở đầu, ví dụ b"\\x00ABC",
        thì bytes_to_int sẽ làm mất thông tin "có byte 0 ở đầu".
        Muốn khôi phục chính xác, cần truyền length ban đầu.
    """
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
    """
    Chuyển text thành số nguyên.

    Args:
        text: Chuỗi văn bản cần chuyển.
        encoding: Bộ mã ký tự, mặc định là utf-8.

    Returns:
        int: Số nguyên biểu diễn chuỗi text.
    """
    if not isinstance(text, str):
        raise TypeError("text phải có kiểu str")

    if not isinstance(encoding, str):
        raise TypeError("encoding phải có kiểu str")

    text_bytes = text.encode(encoding)
    value = bytes_to_int(text_bytes)

    return value


def int_to_text(value: int, encoding: str = "utf-8") -> str:
    """
    Chuyển số nguyên về text.

    Args:
        value: Số nguyên cần chuyển.
        encoding: Bộ mã ký tự, mặc định là utf-8.

    Returns:
        str: Chuỗi text khôi phục từ số nguyên.

    Raises:
        UnicodeDecodeError: Nếu bytes khôi phục không giải mã được.
    """
    if not isinstance(encoding, str):
        raise TypeError("encoding phải có kiểu str")

    text_bytes = int_to_bytes(value)
    text = text_bytes.decode(encoding)

    return text


def read_file_as_bytes(path: str | Path) -> bytes:
    """
    Đọc file dưới dạng bytes.

    Args:
        path: Đường dẫn tới file cần đọc.

    Returns:
        bytes: Nội dung file.
    """
    file_path = Path(path)

    with open(file_path, "rb") as file:
        data = file.read()

    return data


def write_bytes_to_file(data: bytes, path: str | Path) -> None:
    """
    Ghi dữ liệu bytes ra file.

    Args:
        data: Dữ liệu bytes cần ghi.
        path: Đường dẫn file đầu ra.

    Returns:
        None
    """
    if not isinstance(data, bytes):
        raise TypeError("data phải có kiểu bytes")

    file_path = Path(path)

    if file_path.parent != Path("."):
        file_path.parent.mkdir(parents=True, exist_ok=True)

    with open(file_path, "wb") as file:
        file.write(data)


def read_file_as_int(path: str | Path) -> int:
    """
    Đọc file và chuyển nội dung file thành số nguyên.

    Args:
        path: Đường dẫn tới file cần đọc.

    Returns:
        int: Số nguyên biểu diễn nội dung file.
    """
    data = read_file_as_bytes(path)
    value = bytes_to_int(data)

    return value


def write_int_to_file(
    value: int,
    path: str | Path,
    length: int | None = None,
) -> None:
    """
    Chuyển số nguyên thành bytes rồi ghi ra file.

    Args:
        value: Số nguyên cần ghi ra file.
        path: Đường dẫn file đầu ra.
        length: Số byte mong muốn khi chuyển value về bytes.

    Returns:
        None
    """
    data = int_to_bytes(value, length)
    write_bytes_to_file(data, path)


def get_byte_length_from_int(value: int) -> int:
    """
    Tính số byte tối thiểu cần để biểu diễn một số nguyên.

    Args:
        value: Số nguyên cần kiểm tra.

    Returns:
        int: Số byte tối thiểu.
    """
    if not isinstance(value, int):
        raise TypeError("value phải có kiểu int")

    if value < 0:
        raise ValueError("value phải là số nguyên không âm")

    if value == 0:
        return 0

    byte_length = (value.bit_length() + 7) // 8

    return byte_length


def ensure_message_fits_modulus(message_int: int, n: int) -> None:
    """
    Kiểm tra bản rõ dạng số nguyên có nhỏ hơn modulus n không.

    RSA textbook yêu cầu:
        0 <= m < n

    Args:
        message_int: Bản rõ dạng số nguyên m.
        n: Modulus RSA.

    Returns:
        None

    Raises:
        ValueError: Nếu message_int không nằm trong khoảng hợp lệ.
    """
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
