from tkinter import *
from Rsa_core.rsa_core import *
from Number_theory.number_theory import is_coprime
from File_code.file_codec import *
import time
import customtkinter



def build_cipher_tab(cipherrsa):
    def format_time(seconds):
        return f"{seconds:.8f} giây"

    def set_entry_text(entry, text):
        entry.delete(0, "end")
        if text is not None:
            entry.insert(0, text)

    def set_status_text(text, text_color=None):
        if text_color is not None:
            error_value_label.configure(text_color=text_color)
        error_value_label.delete("1.0", "end")
        error_value_label.insert("1.0", text)

    def clear_timing_entries():
        entries = [
            timing_modulus_entry,
            timing_e1_entry,
            timing_d_entry,
            timing_e2_entry,
            timing_encrypt_entry,
            timing_total_entry,
        ]

        for entry in entries:
            entry.delete(0, "end")

    def clear():
        widgets = [input_cipher, output_cipher1, output_cipher2, text_p, text_q, text_e1, text_e2, text_phi, text_d, text_n, text_bit,]

        for widget in widgets:
            widget.delete("1.0", "end")

        clear_timing_entries()
        set_status_text("")

    last_plain_parse_info = {"value": None}

    def result_en():
        try:
            timings = {}
            total_start = time.perf_counter()

            pl = input_cipher.get("1.0", "end-1c").strip()
            p = text_p.get("1.0", "end-1c").strip()
            q = text_q.get("1.0", "end-1c").strip()
            e1 = text_e1.get("1.0", "end-1c").strip()
            e2 = text_e2.get("1.0", "end-1c").strip()
            phi = text_phi.get("1.0", "end-1c").strip()
            n = text_n.get("1.0", "end-1c").strip()
            bit = text_bit.get("1.0", "end-1c").strip()

            if not pl:
                raise ValueError("Hãy nhập bản rõ!")

            plain_parse_info = parse_input_to_int(pl)
            m = plain_parse_info["value"]

            last_plain_parse_info["value"] = plain_parse_info

            if not bit:
                bit = 1024
            else:
                bit = parse_number_input(bit)

            if bit < 16:
                raise ValueError("Bit nên lớn hơn hoặc bằng 16!")
            start = time.perf_counter()
            if p and q:
                p = parse_number_input(p)
                q = parse_number_input(q)

                if p <= 1 or q <= 1:
                    raise ValueError("p và q phải lớn hơn 1!")

                n = p * q
                phi = (p - 1) * (q - 1)

                text_n.delete("1.0", "end")
                text_n.insert("1.0", str(n))

                text_phi.delete("1.0", "end")
                text_phi.insert("1.0", str(phi))

            elif n and phi:
                n = parse_number_input(n)
                phi = parse_number_input(phi)

                if n <= 1:
                    raise ValueError("N phải lớn hơn 1!")

                if phi <= 1:
                    raise ValueError("Phi phải lớn hơn 1!")

            elif not p and not q and not n and not phi:
                result_modulus = generate_shared_modulus(bit)

                p = result_modulus["p"]
                q = result_modulus["q"]
                n = result_modulus["n"]
                phi = result_modulus["phi"]
                

                text_p.delete("1.0", "end")
                text_p.insert("1.0", str(p))

                text_q.delete("1.0", "end")
                text_q.insert("1.0", str(q))

                text_n.delete("1.0", "end")
                text_n.insert("1.0", str(n))

                text_phi.delete("1.0", "end")
                text_phi.insert("1.0", str(phi))
            
            else:
                raise ValueError(
                    "Hãy nhập đủ p và q, hoặc nhập đủ n và phi, hoặc để trống để chương trình tự sinh!"
                )
            timings["Tính/Sinh p, q, n, phi"] = time.perf_counter() - start
            ensure_message_fits_modulus(m, n)
            start = time.perf_counter()
            if e1:
                e1 = parse_number_input(e1)
            else:
                e1 = choose_public_exponent(phi)

                text_e1.delete("1.0", "end")
                text_e1.insert("1.0", str(e1))
            timings["Chọn/kiểm tra e1"] = time.perf_counter() - start
            if not (1 < e1 < phi):
                raise ValueError("E1 phải thuộc khoảng (1, phi)!")

            if not is_coprime(e1, phi):
                raise ValueError("E1 không nguyên tố cùng nhau với phi!")
            start = time.perf_counter()
            result_key1 = generate_rsa_key_with_shared_n(n, phi, e1)
            d = result_key1["d"]
            
            text_d.delete("1.0", "end")
            text_d.insert("1.0", str(d))
            timings["Tính khóa riêng d"] = time.perf_counter() - start
            start = time.perf_counter()
            if e2:
                e2 = parse_number_input(e2)

                if e2 == e1:
                    raise ValueError("E2 phải khác e1!")

                if not (1 < e2 < phi):
                    raise ValueError("E2 phải thuộc khoảng (1, phi)!")

                if not is_coprime(e2, phi):
                    raise ValueError("E2 không nguyên tố cùng nhau với phi!")

                if not is_coprime(e1, e2):
                    raise ValueError("E1 và e2 phải nguyên tố cùng nhau để tấn công modulus chung!")

            else:
                e2 = choose_public_exponent(
                    phi,
                    avoid={e1},
                    coprime_with={e1},
                )

                text_e2.delete("1.0", "end")
                text_e2.insert("1.0", str(e2))
            timings["Chọn/kiểm tra e2"] = time.perf_counter() - start
            start = time.perf_counter()
            c1 = rsa_encrypt_int(m, e1, n)
            c2 = rsa_encrypt_int(m, e2, n)
            timings["Mã hóa C1, C2"] = time.perf_counter() - start
            output_cipher1.delete("1.0", "end")
            output_cipher1.insert("1.0", str(c1))

            output_cipher2.delete("1.0", "end")
            output_cipher2.insert("1.0", str(c2))

            set_status_text(
                "Mã hóa thành công! Đã tạo C1 và C2 bằng hai khóa công khai dùng chung n.",
                text_color="green",
            )

        except ValueError as error:
            set_status_text(str(error), text_color="red")

        except TypeError as error:
            set_status_text(str(error), text_color="red")

        except Exception as error:
            set_status_text(f"Không xác định: {error}", text_color="red")
        timings["Tổng thời gian"] = time.perf_counter() - total_start
        set_entry_text(timing_modulus_entry, format_time(timings.get("Tính/Sinh p, q, n, phi", 0)))
        set_entry_text(timing_e1_entry, format_time(timings.get("Chọn/kiểm tra e1", 0)))
        set_entry_text(timing_d_entry, format_time(timings.get("Tính khóa riêng d", 0)))
        set_entry_text(timing_e2_entry, format_time(timings.get("Chọn/kiểm tra e2", 0)))
        set_entry_text(timing_encrypt_entry, format_time(timings.get("Mã hóa C1, C2", 0)))
        set_entry_text(timing_total_entry, format_time(timings.get("Tổng thời gian", 0)))

    def result_de():
        try:
            cp = input_cipher.get("1.0", "end-1c").strip()
            d = text_d.get("1.0", "end-1c").strip()
            n = text_n.get("1.0", "end-1c").strip()

            if not cp:
                raise ValueError("Hãy nhập bản mã!")

            if not d:
                raise ValueError("Hãy nhập khóa riêng d!")

            if not n:
                raise ValueError("Hãy nhập modulus n!")

            cp = parse_number_input(cp)
            d = parse_number_input(d)
            n = parse_number_input(n)

            pl = rsa_decrypt_int(cp, d, n)

            output_cipher1.delete("1.0", "end")
            output_cipher1.insert("1.0", str(pl))

            parse_info = last_plain_parse_info.get("value")
            display_plaintext = int_to_format(pl, parse_info)

            output_cipher2.delete("1.0", "end")
            output_cipher2.insert("1.0", display_plaintext)

            set_status_text("Giải mã thành công!", text_color="green")

        except ValueError as error:
            set_status_text(str(error), text_color="red")

        except TypeError as error:
            set_status_text(str(error), text_color="red")

        except Exception as error:
            set_status_text(f"Không xác định: {error}", text_color="red")

    compact_pad_x = 8
    compact_pad_y = 4
    section_gap = 6
    input_height = 74
    output_height = 34
    value_height = 50

    layout_frame = customtkinter.CTkFrame(cipherrsa)
    layout_frame.pack(fill="both", expand=True)
    layout_frame.grid_columnconfigure(0, weight=6)
    layout_frame.grid_columnconfigure(1, weight=5)
    layout_frame.grid_rowconfigure(0, weight=1)

    # khung nhap tong quat
    cipher_frame = customtkinter.CTkFrame(layout_frame)
    cipher_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 4), pady=0)
    cipher_frame.grid_columnconfigure(0, weight=5)
    cipher_frame.grid_columnconfigure(1, weight=5)
    cipher_frame.grid_rowconfigure(0, weight=1)

    input_frame = customtkinter.CTkFrame(cipher_frame)
    input_frame.grid(row = 0, column = 0, sticky="nsew", padx=(0, 4), pady=compact_pad_y)
    label_input = customtkinter.CTkLabel(input_frame, text="Đầu vào", anchor="w")
    label_input.pack(padx = compact_pad_x, pady=(6, 2), fill="x")
    input_cipher = customtkinter.CTkTextbox(input_frame, height=input_height)
    input_cipher.pack(padx = compact_pad_x, pady = (0, compact_pad_y), fill="both", expand=True)

    output_frame = customtkinter.CTkFrame(cipher_frame)
    output_frame.grid(row = 0, column = 1, sticky="nsew", padx=(4, 0), pady=compact_pad_y)
    label_output = customtkinter.CTkLabel(output_frame, text="Đầu ra", anchor="w")
    label_output.pack(padx = compact_pad_x, pady=(6, 2), fill="x")
    output_cipher1 = customtkinter.CTkTextbox(output_frame, height=output_height)
    output_cipher1.pack(padx = compact_pad_x, pady = (0, 3), fill="both", expand=True)
    output_cipher2 = customtkinter.CTkTextbox(output_frame, height=output_height)
    output_cipher2.pack(padx = compact_pad_x, pady=(3, compact_pad_y), fill="both", expand=True)

    # Khung gia tri di kem
    value_panel = customtkinter.CTkFrame(layout_frame)
    value_panel.grid(row=0, column=1, sticky="nsew", padx=(4, 0), pady=0)
    value_panel.grid_columnconfigure(0, weight=1)

    label_ele = customtkinter.CTkLabel(value_panel, text="Các giá trị hữu dụng", anchor="w")
    label_ele.pack(fill="x", padx=compact_pad_x, pady=(6, 2))
    value_ele_frame = customtkinter.CTkFrame(value_panel)
    value_ele_frame.pack(fill="x", padx=compact_pad_x, pady=(0, compact_pad_y))
    value_ele_frame.grid_columnconfigure(0, weight=5)
    value_ele_frame.grid_columnconfigure(1, weight=5)

    ele_first_frame = customtkinter.CTkFrame(value_ele_frame)
    ele_first_frame.grid(row = 0, column = 0, sticky = "nsew", padx=(0, 4), pady=compact_pad_y)
    ele_first_frame.grid_columnconfigure(0, weight=0, minsize=42)
    ele_first_frame.grid_columnconfigure(1, weight=1)

    label_p = customtkinter.CTkLabel(ele_first_frame, text = "p", anchor="w", width=36)
    label_p.grid(row = 0, column = 0, sticky="ew", padx=(compact_pad_x, 4), pady=3)
    text_p = customtkinter.CTkTextbox(ele_first_frame, height=value_height)
    text_p.grid(row = 0, column = 1, sticky="ew", padx=(4, compact_pad_x), pady = 3)
    label_e1 = customtkinter.CTkLabel(ele_first_frame, text = "e1", anchor="w", width=36)
    label_e1.grid(row = 1, column = 0, sticky="ew", padx=(compact_pad_x, 4), pady=3)
    text_e1 = customtkinter.CTkTextbox(ele_first_frame, height=value_height)
    text_e1.grid(row = 1, column = 1, sticky="ew", padx=(4, compact_pad_x), pady = 3)
    label_phi = customtkinter.CTkLabel(ele_first_frame, text = "phi", anchor="w", width=36)
    label_phi.grid(row = 2, column = 0, sticky="ew", padx=(compact_pad_x, 4), pady=3)
    text_phi = customtkinter.CTkTextbox(ele_first_frame, height=value_height)
    text_phi.grid(row = 2, column = 1, sticky="ew", padx=(4, compact_pad_x), pady = 3)
    label_d = customtkinter.CTkLabel(ele_first_frame, text = "d", anchor="w", width=36)
    label_d.grid(row = 3, column = 0, sticky="ew", padx=(compact_pad_x, 4), pady=(3, compact_pad_y))
    text_d = customtkinter.CTkTextbox(ele_first_frame, height=value_height)
    text_d.grid(row = 3, column = 1, sticky="ew", padx=(4, compact_pad_x), pady = (3, compact_pad_y))

    ele_second_frame = customtkinter.CTkFrame(value_ele_frame)
    ele_second_frame.grid(row = 0, column = 1, sticky = "nsew", padx=(4, 0), pady=compact_pad_y)
    ele_second_frame.grid_columnconfigure(0, weight=0, minsize=42)
    ele_second_frame.grid_columnconfigure(1, weight=1)

    label_q = customtkinter.CTkLabel(ele_second_frame, text = "q", anchor="w", width=36)
    label_q.grid(row = 0, column = 0, sticky="ew", padx=(compact_pad_x, 4), pady=3)
    text_q = customtkinter.CTkTextbox(ele_second_frame, height=value_height)
    text_q.grid(row = 0, column = 1, sticky="ew", padx=(4, compact_pad_x), pady = 3)
    label_e2 = customtkinter.CTkLabel(ele_second_frame, text = "e2", anchor="w", width=36)
    label_e2.grid(row = 1, column = 0, sticky="ew", padx=(compact_pad_x, 4), pady=3)
    text_e2 = customtkinter.CTkTextbox(ele_second_frame, height=value_height)
    text_e2.grid(row = 1, column = 1, sticky="ew", padx=(4, compact_pad_x), pady = 3)
    label_n = customtkinter.CTkLabel(ele_second_frame, text = "n", anchor="w", width=36)
    label_n.grid(row = 2, column = 0, sticky="ew", padx=(compact_pad_x, 4), pady=3)
    text_n = customtkinter.CTkTextbox(ele_second_frame, height=value_height)
    text_n.grid(row = 2, column = 1, sticky="ew", padx=(4, compact_pad_x), pady = 3)
    label_bit = customtkinter.CTkLabel(ele_second_frame, text = "bit", anchor="w", width=36)
    label_bit.grid(row = 3, column = 0, sticky="ew", padx=(compact_pad_x, 4), pady=(3, compact_pad_y))
    text_bit = customtkinter.CTkTextbox(ele_second_frame, height=value_height)
    text_bit.grid(row = 3, column = 1, sticky="ew", padx=(4, compact_pad_x), pady = (3, compact_pad_y))

    # khung cac nut bam
    label_button = customtkinter.CTkLabel(value_panel, text="Chức năng", anchor="w")
    label_button.pack(fill="x", padx=compact_pad_x, pady=(section_gap, 2))
    button_frame = customtkinter.CTkFrame(value_panel)
    button_frame.pack(fill="x", padx=compact_pad_x, pady=(0, compact_pad_y))
    button_frame.grid_columnconfigure(0, weight=1)
    button_frame.grid_columnconfigure(1, weight=1)
    button_frame.grid_columnconfigure(2, weight=1)

    button_en = customtkinter.CTkButton(button_frame, text="Mã hóa", command=result_en)
    button_en.grid(row = 0, column = 0, sticky="ew", padx=(compact_pad_x, 3), pady=compact_pad_y)

    button_de = customtkinter.CTkButton(button_frame, text = "Giải mã", command=result_de)
    button_de.grid(row = 0, column = 1, sticky="ew", padx=3, pady=compact_pad_y)

    button_clear = customtkinter.CTkButton(button_frame, text="Làm mới", command=clear)
    button_clear.grid(row = 0, column = 2, sticky="ew", padx=(3, compact_pad_x), pady=compact_pad_y)

    bottom_frame = customtkinter.CTkFrame(cipherrsa)
    bottom_frame.pack(fill="both", expand=True, pady=(section_gap, 0))
    bottom_frame.grid_columnconfigure(0, weight=6)
    bottom_frame.grid_columnconfigure(1, weight=5)
    bottom_frame.grid_rowconfigure(0, weight=1)

    # khung loi
    error_card = customtkinter.CTkFrame(bottom_frame)
    error_card.grid(row=0, column=0, sticky="nsew", padx=(0, 4), pady=0)

    error_title_label = customtkinter.CTkLabel(error_card, text="Trạng thái", anchor="w")
    error_title_label.pack(fill="x", padx=compact_pad_x, pady=(6, 2))

    error_value_label = customtkinter.CTkTextbox(error_card, height=100)
    error_value_label.pack(fill="x", padx=compact_pad_x, pady=(0, compact_pad_y))

    # khung thoi gian
    timing_card = customtkinter.CTkFrame(bottom_frame)
    timing_card.grid(row=0, column=1, sticky="nsew", padx=(4, 0), pady=0)

    timing_title_label = customtkinter.CTkLabel(timing_card, text="Thời gian xử lý", anchor="w")
    timing_title_label.pack(fill="x", padx=compact_pad_x, pady=(6, 2))

    timing_table_frame = customtkinter.CTkFrame(timing_card)
    timing_table_frame.pack(fill="x", padx=compact_pad_x, pady=(0, compact_pad_y))
    timing_table_frame.grid_columnconfigure(0, weight=0, minsize=220)
    timing_table_frame.grid_columnconfigure(1, weight=1)

    timing_modulus_label = customtkinter.CTkLabel(timing_table_frame, text="Thời gian chọn p, q, n, phi", anchor="w")
    timing_modulus_label.grid(row=0, column=0, sticky="ew", padx=(compact_pad_x, 4), pady=3)
    timing_modulus_entry = customtkinter.CTkEntry(timing_table_frame, height=28)
    timing_modulus_entry.grid(row=0, column=1, sticky="ew", padx=(4, compact_pad_x), pady=3)

    timing_e1_label = customtkinter.CTkLabel(timing_table_frame, text="Thời gian chọn e1", anchor="w")
    timing_e1_label.grid(row=1, column=0, sticky="ew", padx=(compact_pad_x, 4), pady=3)
    timing_e1_entry = customtkinter.CTkEntry(timing_table_frame, height=28)
    timing_e1_entry.grid(row=1, column=1, sticky="ew", padx=(4, compact_pad_x), pady=3)

    timing_d_label = customtkinter.CTkLabel(timing_table_frame, text="Thời gian tính d", anchor="w")
    timing_d_label.grid(row=2, column=0, sticky="ew", padx=(compact_pad_x, 4), pady=3)
    timing_d_entry = customtkinter.CTkEntry(timing_table_frame, height=28)
    timing_d_entry.grid(row=2, column=1, sticky="ew", padx=(4, compact_pad_x), pady=3)

    timing_e2_label = customtkinter.CTkLabel(timing_table_frame, text="Thời gian chọn e2", anchor="w")
    timing_e2_label.grid(row=3, column=0, sticky="ew", padx=(compact_pad_x, 4), pady=3)
    timing_e2_entry = customtkinter.CTkEntry(timing_table_frame, height=28)
    timing_e2_entry.grid(row=3, column=1, sticky="ew", padx=(4, compact_pad_x), pady=3)

    timing_encrypt_label = customtkinter.CTkLabel(timing_table_frame, text="Thời gian mã hóa", anchor="w")
    timing_encrypt_label.grid(row=4, column=0, sticky="ew", padx=(compact_pad_x, 4), pady=3)
    timing_encrypt_entry = customtkinter.CTkEntry(timing_table_frame, height=28)
    timing_encrypt_entry.grid(row=4, column=1, sticky="ew", padx=(4, compact_pad_x), pady=3)

    timing_total_label = customtkinter.CTkLabel(timing_table_frame, text="Tổng thời gian xử lý", anchor="w")
    timing_total_label.grid(row=5, column=0, sticky="ew", padx=(compact_pad_x, 4), pady=(3, compact_pad_y))
    timing_total_entry = customtkinter.CTkEntry(timing_table_frame, height=28)
    timing_total_entry.grid(row=5, column=1, sticky="ew", padx=(4, compact_pad_x), pady=(3, compact_pad_y))

    
