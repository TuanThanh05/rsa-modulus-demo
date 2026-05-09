import pytest

from src.file_codec import bytes_to_int
from src.file_codec import int_to_bytes
from src.file_codec import text_to_int
from src.file_codec import int_to_text
from src.file_codec import read_file_as_bytes
from src.file_codec import write_bytes_to_file
from src.file_codec import read_file_as_int
from src.file_codec import write_int_to_file
from src.file_codec import get_byte_length_from_int
from src.file_codec import ensure_message_fits_modulus


def test_bytes_to_int_basic():
    data = b"ABC"

    value = bytes_to_int(data)

    assert value == 4276803


def test_int_to_bytes_basic():
    value = 4276803

    data = int_to_bytes(value)

    assert data == b"ABC"


def test_bytes_int_round_trip():
    original_data = b"HELLO PTIT"

    value = bytes_to_int(original_data)

    recovered_data = int_to_bytes(value)

    assert recovered_data == original_data


def test_text_int_round_trip_ascii():
    original_text = "HELLO COMMON MODULUS"

    value = text_to_int(original_text)

    recovered_text = int_to_text(value)

    assert recovered_text == original_text


def test_text_int_round_trip_vietnamese():
    original_text = "Xin chào Thành"

    value = text_to_int(original_text)

    recovered_text = int_to_text(value)

    assert recovered_text == original_text


def test_empty_bytes_to_int():
    value = bytes_to_int(b"")

    assert value == 0


def test_zero_int_to_bytes_without_length():
    data = int_to_bytes(0)

    assert data == b""


def test_zero_int_to_bytes_with_length():
    data = int_to_bytes(0, length=3)

    assert data == b"\x00\x00\x00"


def test_int_to_bytes_with_leading_zero_length():
    original_data = b"\x00ABC"

    value = bytes_to_int(original_data)

    recovered_data = int_to_bytes(value, length=4)

    assert recovered_data == original_data


def test_int_to_bytes_length_too_small():
    value = bytes_to_int(b"ABC")

    with pytest.raises(ValueError):
        int_to_bytes(value, length=2)


def test_int_to_bytes_negative_value():
    with pytest.raises(ValueError):
        int_to_bytes(-1)


def test_get_byte_length_from_int():
    value = bytes_to_int(b"ABC")

    byte_length = get_byte_length_from_int(value)

    assert byte_length == 3


def test_ensure_message_fits_modulus_valid():
    message_int = 30
    n = 247

    result = ensure_message_fits_modulus(message_int, n)

    assert result is None


def test_ensure_message_fits_modulus_invalid():
    message_int = 247
    n = 247

    with pytest.raises(ValueError):
        ensure_message_fits_modulus(message_int, n)


def test_read_file_as_bytes_and_write_bytes_to_file(tmp_path):
    file_path = tmp_path / "demo.txt"

    write_bytes_to_file(b"HELLO FILE", file_path)

    data = read_file_as_bytes(file_path)

    assert data == b"HELLO FILE"


def test_read_file_as_int_and_write_int_to_file(tmp_path):
    input_path = tmp_path / "input.txt"
    output_path = tmp_path / "output.txt"

    write_bytes_to_file(b"HELLO FILE", input_path)

    value = read_file_as_int(input_path)

    write_int_to_file(value, output_path)

    recovered_data = read_file_as_bytes(output_path)

    assert recovered_data == b"HELLO FILE"
