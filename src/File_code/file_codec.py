def bytes_to_int(data: bytes) -> int:
    if not isinstance(data, bytes):
        raise TypeError("Data phải là kiểu ")
    if data == b"":
        return 0
    value = int.from_bytes(data, byteorder="big")
    return value


def int_to_bytes(value: int, length: int | None = None) -> bytes:
    if not isinstance(value, int):
        raise TypeError(f"{value} phải là kiểu 'int'")
    if value < 0:
        raise ValueError(f"{value} phải là số nguyên không âm")
    if length is not None:
        if not isinstance(length, int):
            raise TypeError(f"{length} phải là kiểu 'int' hoặc 'none'")
        if length < 0:
            raise ValueError(f"{length} phải là số nguyên không âm")
    if value == 0:
        if length is None:
            return b""
        return bytes(length)
    
    minimum_length = (value.bit_length() + 7) // 8
    if length is None:
        length = minimum_length
    if length < minimum_length:
        raise ValueError(f"{length} không đủ để biểu diễn bytes")
    data = value.to_bytes(length, byteorder="big")
    return data


def text_to_int(text: str, encoding: str = "utf-8") -> int:
    if not isinstance(text, str):
        raise TypeError(f"{text} phải có kiểu 'str'")
    if not isinstance(encoding, str):
        raise TypeError(f"{encoding} phải có kiểu 'str'")
    text_bytes = text.encode(encoding)
    value = bytes_to_int(text_bytes)
    return value


def int_to_text(value: int, encoding: str = "utf-8", length: int | None = None) -> str:
    if not isinstance(encoding, str):
        raise TypeError(f"{encoding} phải có kiểu 'str'")
    text_bytes = int_to_bytes(value, length=length)
    text = text_bytes.decode(encoding)
    return text


def get_byte_length_from_int(value: int) -> int:
    if not isinstance(value, int):
        raise TypeError(f"{value} phải là kiểu 'int'")
    if value < 0:
        raise ValueError(f"{value} phải là số nguyên không âm")
    if value == 0:
        return 0
    byte_length = (value.bit_length() + 7) // 8
    return byte_length


def ensure_message_fits_modulus(message_int: int, n: int) -> None:
    if not isinstance(message_int, int):
        raise TypeError(f"{message_int} phải là kiểu 'int'")
    if not isinstance(n, int):
        raise TypeError(f"{n} phải là kiểu 'int'")
    if n <= 1:
        raise ValueError(f"{n} phải là số nguyên không lớn hơn 1")
    if not (0 <= message_int < n):
        raise ValueError(
            "Bản rõ dạng số nguyên phải thuộc [0, n). Hãy dùng văn bản ngắn hơn hoặc sinh modulus n lớn hơn."
        )


def make_parse_result(value, kind, raw, encoding: str | None = None, byte_length: int | None = None):
    result = {
        "value": value,
        "kind": kind,
        "raw": raw,
        "encoding": encoding,
        "byte_length": byte_length,
    }

    return result

def parse_input_to_int( user_input: str | int | bytes, encoding: str = "utf-8", default_text: bool = True):
    if isinstance(user_input, int):
        return make_parse_result(
            value=user_input,
            kind="dec",
            raw=str(user_input),
        )

    if isinstance(user_input, bytes):
        value = bytes_to_int(user_input)

        return make_parse_result(
            value=value,
            kind="bytes",
            raw=str(user_input),
            encoding=None,
            byte_length=len(user_input),
        )

    if not isinstance(user_input, str):
        raise TypeError("Đầu vào phải là 'str', 'int', 'bytes'")

    raw_text = user_input.strip()

    if raw_text == "":
        raise ValueError("Không thể chuyển dữ liệu rỗng sang số nguyên")

    lower_text = raw_text.lower()
    compact = raw_text.replace(" ", "").replace("_", "")
    compact_lower = compact.lower()

    if lower_text.startswith("text:"):
        text_value = raw_text[5:]
        data = text_value.encode(encoding)
        value = bytes_to_int(data)

        return make_parse_result(
            value=value,
            kind="text",
            raw=text_value,
            encoding=encoding,
            byte_length=len(data),
        )

    if compact_lower.startswith("dec:"):
        number_part = compact[4:]
        value = int(number_part, 10)

        return make_parse_result(value=value, kind="dec", raw=raw_text)

    if compact_lower.startswith("hex:"):
        number_part = compact[4:]
        value = int(number_part, 16)

        return make_parse_result(value=value, kind="hex", raw=raw_text)

    if compact_lower.startswith("bin:"):
        number_part = compact[4:]

        if not all(ch in "01" for ch in number_part):
            raise ValueError("Dữ liệu sau hệ hai: không hợp lệ")

        value = int(number_part, 2)

        return make_parse_result(value=value, kind="bin", raw=raw_text)

    if compact_lower.startswith("oct:"):
        number_part = compact[4:]

        if not all(ch in "01234567" for ch in number_part):
            raise ValueError("Dữ liệu sau hệ tám: không hợp lệ")

        value = int(number_part, 8)

        return make_parse_result(value=value, kind="oct", raw=raw_text)

    if compact_lower.startswith("0x"):
        value = int(compact, 16)

        return make_parse_result(value=value, kind="hex", raw=raw_text)

    if compact_lower.startswith("0b"):
        value = int(compact, 2)

        return make_parse_result(value=value, kind="bin", raw=raw_text, )

    if compact_lower.startswith("0o"):
        value = int(compact, 8)

        return make_parse_result(value=value, kind="oct", raw=raw_text)

    if compact_lower.endswith("h"):
        number_part = compact[:-1]
        value = int(number_part, 16)

        return make_parse_result(value=value, kind="hex", raw=raw_text)

    if compact_lower.endswith("b"):
        number_part = compact[:-1]

        if number_part != "" and all(ch in "01" for ch in number_part):
            value = int(number_part, 2)

            return make_parse_result(value=value, kind="bin", raw=raw_text)

    if compact_lower.endswith("o"):
        number_part = compact[:-1]

        if number_part != "" and all(ch in "01234567" for ch in number_part):
            value = int(number_part, 8)

            return make_parse_result(value=value, kind="oct", raw=raw_text)

    if compact_lower.endswith("d"):
        number_part = compact[:-1]

        if number_part != "" and number_part.isdigit():
            value = int(number_part, 10)

            return make_parse_result(value=value, kind="dec", raw=raw_text)

    if compact.isdigit():
        value = int(compact, 10)

        return make_parse_result(value=value, kind="dec", raw=raw_text)

    hex_chars = "0123456789abcdefABCDEF"

    if all(ch in hex_chars for ch in compact) and any(ch in "abcdefABCDEF" for ch in compact):
        value = int(compact, 16)

        return make_parse_result(value=value, kind="hex", raw=raw_text )

    if default_text:
        data = raw_text.encode(encoding)
        value = bytes_to_int(data)

        return make_parse_result(
            value=value,
            kind="text",
            raw=raw_text,
            encoding=encoding,
            byte_length=len(data),
        )

    raise ValueError("Không nhận dạng được định dạng dữ liệu")

def int_to_format(value, parse_info: dict[str, int | str | None] | None = None ):
    if not isinstance(value, int):
        raise TypeError(f"{value} phải có kiểu 'int'")

    if value < 0:
        raise ValueError(f"{value} phải là số nguyên không âm")

    if parse_info is None:
        return str(value)

    kind = parse_info.get("kind")
    encoding = parse_info.get("encoding")
    byte_length = parse_info.get("byte_length")

    if kind == "dec":
        return str(value)

    if kind == "hex":
        return hex(value)

    if kind == "bin":
        return bin(value)

    if kind == "oct":
        return oct(value)

    if kind == "bytes":
        if isinstance(byte_length, int):
            data = int_to_bytes(value, length=byte_length)
        else:
            data = int_to_bytes(value)

        return str(data)

    if kind == "text":
        if not isinstance(encoding, str):
            encoding = "utf-8"

        length = byte_length if isinstance(byte_length, int) else None

        try:
            return int_to_text(value, encoding=encoding, length=length)
        except UnicodeDecodeError:
            return str(value)

    return str(value)

def parse_number_input(user_input: str | int):
    result = parse_input_to_int(user_input, default_text=False)

    value = result["value"]

    if not isinstance(value, int):
        raise TypeError("Giá trị sau khi parse không phải int")

    return value

def format_attack_result_all(value: int) -> dict[str, str]:
    if not isinstance(value, int):
        raise TypeError(f"{value} phải có kiểu 'int'")

    if value < 0:
        raise ValueError(f"{value} phải là số nguyên không âm")

    decimal_value = str(value)
    hex_value = hex(value)
    binary_value = bin(value)
    octal_value = oct(value)

    try:
        utf8_text = int_to_text(value, encoding="utf-8")
    except UnicodeDecodeError:
        utf8_text = "Không thể chuyển sang UTF-8"
    except ValueError:
        utf8_text = "Không thể chuyển sang UTF-8"

    result = {
        "decimal": decimal_value,
        "text": utf8_text,
        "hex": hex_value,
        "binary": binary_value,
        "octal": octal_value,
    }

    return result
