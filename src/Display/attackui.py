from tkinter import *
import customtkinter
from Attack_rsa_core.common_modulus_attack import common_modulus_attack
from File_code.file_codec import *

def build_attack_tab(attackrsa):
    def format_time(seconds):
        return f"{seconds:.8f} giây"

    def set_status_text(text, text_color=None):
        if text_color is not None:
            error_value_label.configure(text_color=text_color)
        error_value_label.delete("1.0", "end")
        error_value_label.insert("1.0", text)

    def clear_inputs():
        ciphertext1_entry.delete(0, "end")
        ciphertext2_entry.delete(0, "end")
        modulus_entry.delete(0, "end")
        public_e1_entry.delete(0, "end")
        public_e2_entry.delete(0, "end")

        modulus_value_label.delete("1.0", "end")

        c1_base_value_label.delete("1.0", "end")
        c1_exponent_value_label.delete("1.0", "end")
        c1_inverse_value_label.delete("1.0", "end")
        c1_result_value_label.delete("1.0", "end")
        c1_time_value_label.delete("1.0", "end")

        c2_base_value_label.delete("1.0", "end")
        c2_exponent_value_label.delete("1.0", "end")
        c2_inverse_value_label.delete("1.0", "end")
        c2_result_value_label.delete("1.0", "end")
        c2_time_value_label.delete("1.0", "end")

        final_mod_value_label.delete("1.0", "end")
        final_mod_value_label.insert("1.0", "Kết quả mod:")

        result_decimal_value_label.delete("1.0", "end")
        result_text_value_label.delete("1.0", "end")
        result_hex_value_label.delete("1.0", "end")
        result_binary_value_label.delete("1.0", "end")
        result_octal_value_label.delete("1.0", "end")
        result_time_value_label.delete("1.0", "end")

        set_status_text("")

        attackrsa.winfo_toplevel().focus_set()

    def run_attack():
        try:
            c1 = parse_number_input(ciphertext1_entry.get().strip())
            c2 = parse_number_input(ciphertext2_entry.get().strip())
            n = parse_number_input(modulus_entry.get().strip())
            e1 = parse_number_input(public_e1_entry.get().strip())
            e2 = parse_number_input(public_e2_entry.get().strip())

            recovered_m, trace = common_modulus_attack(c1, c2, e1, e2, n)

            c1_trace = trace["trace_resultc1"]
            c2_trace = trace["trace_resultc2"]
            timing = trace["timing"]

            modulus_value_label.delete("1.0", "end")
            modulus_value_label.insert("1.0", str(n))

            c1_base_value_label.delete("1.0", "end")
            c1_base_value_label.insert("1.0", str(c1_trace["original_base"]))
            c1_exponent_value_label.delete("1.0", "end")
            c1_exponent_value_label.insert("1.0", str(c1_trace["original_exponent"]))
            c1_inverse_value_label.delete("1.0", "end")
            c1_inverse_value_label.insert("1.0", str(c1_trace.get("inverse_base", "Không dùng")))
            c1_result_value_label.delete("1.0", "end")
            c1_result_value_label.insert("1.0", str(trace["resultc1"]))
            c1_time_value_label.delete("1.0", "end")
            c1_time_value_label.insert("1.0", format_time(timing["c1modn"]))

            c2_base_value_label.delete("1.0", "end")
            c2_base_value_label.insert("1.0", str(c2_trace["original_base"]))
            c2_exponent_value_label.delete("1.0", "end")
            c2_exponent_value_label.insert("1.0", str(c2_trace["original_exponent"]))
            c2_inverse_value_label.delete("1.0", "end")
            c2_inverse_value_label.insert("1.0", str(c2_trace.get("inverse_base", "Không dùng")))
            c2_result_value_label.delete("1.0", "end")
            c2_result_value_label.insert("1.0", str(trace["resultc2"]))
            c2_time_value_label.delete("1.0", "end")
            c2_time_value_label.insert("1.0", format_time(timing["c2modn"]))                                                                                             
            
            final_mod_value_label.delete("1.0", "end")
            final_mod_value_label.insert("1.0", f"Kết quả mod: {recovered_m}")

            result_type = format_attack_result_all(recovered_m)

            result_decimal_value_label.delete("1.0", "end")
            result_decimal_value_label.insert("1.0", result_type["decimal"])

            result_text_value_label.delete("1.0", "end")
            result_text_value_label.insert("1.0", result_type["text"])

            result_hex_value_label.delete("1.0", "end")
            result_hex_value_label.insert("1.0", result_type["hex"])

            result_binary_value_label.delete("1.0", "end")
            result_binary_value_label.insert("1.0", result_type["binary"])

            result_octal_value_label.delete("1.0", "end")
            result_octal_value_label.insert("1.0", result_type["octal"])

            result_time_value_label.delete("1.0", "end")
            result_time_value_label.insert("1.0", format_time(timing["total_time"]))


            set_status_text("Không có lỗi", text_color="green")

        except Exception as error:
            set_status_text(f"{error}", text_color="red")

    compact_pad_x = 8
    compact_pad_y = 4
    section_gap = 6
    value_height = 40
    small_value_height = 32

    # khung nhap

    input_card = customtkinter.CTkFrame(attackrsa)
    input_card.pack(fill="x", pady=(0, section_gap))

    input_card.grid_columnconfigure(0, weight=5)
    input_card.grid_columnconfigure(1, weight=5)
    input_card.grid_columnconfigure(2, weight=2)
    input_card.grid_rowconfigure(0, weight=1)


    # khung ban ma

    ciphertext_card = customtkinter.CTkFrame(input_card)
    ciphertext_card.grid(row=0, column=0, sticky="nsew", padx=(0, 4), pady=4)

    ciphertext_title_label = customtkinter.CTkLabel(ciphertext_card, text="Bản mã đầu vào", anchor="w")
    ciphertext_title_label.pack(fill="x", padx=compact_pad_x, pady=(6, 2))

    ciphertext_form_frame = customtkinter.CTkFrame(ciphertext_card)
    ciphertext_form_frame.pack(fill="x", padx=compact_pad_x, pady=(0, compact_pad_y))

    ciphertext_form_frame.grid_columnconfigure(0, weight=1)

    ciphertext1_entry = customtkinter.CTkEntry(ciphertext_form_frame, placeholder_text="Nhập bản mã 1")
    ciphertext1_entry.grid(row=0, column=0, sticky="ew", padx=compact_pad_x, pady=(compact_pad_y, 3))

    ciphertext2_entry = customtkinter.CTkEntry(ciphertext_form_frame, placeholder_text="Nhập bản mã 2")
    ciphertext2_entry.grid(row=1, column=0, sticky="ew", padx=compact_pad_x, pady=(3, compact_pad_y))


    # khung khoa cong khai

    public_key_card = customtkinter.CTkFrame(input_card)
    public_key_card.grid(row=0, column=1, sticky="nsew", padx=(4, 0), pady=4)

    public_key_title_label = customtkinter.CTkLabel(public_key_card, text="Khóa công khai", anchor="w")
    public_key_title_label.pack(fill="x", padx=compact_pad_x, pady=(6, 2))

    public_key_form_frame = customtkinter.CTkFrame(public_key_card)
    public_key_form_frame.pack(fill="x", padx=compact_pad_x, pady=(0, compact_pad_y))

    public_key_form_frame.grid_columnconfigure(0, weight=1)

    modulus_entry = customtkinter.CTkEntry(public_key_form_frame, placeholder_text="Nhập modulus n")
    modulus_entry.grid(row=0, column=0, sticky="ew", padx=compact_pad_x, pady=(compact_pad_y, 3))

    public_e1_entry = customtkinter.CTkEntry(public_key_form_frame, placeholder_text="Nhập số e1")
    public_e1_entry.grid(row=1, column=0, sticky="ew", padx=compact_pad_x, pady=3)

    public_e2_entry = customtkinter.CTkEntry(public_key_form_frame, placeholder_text="Nhập số e2")
    public_e2_entry.grid(row=2, column=0, sticky="ew", padx=compact_pad_x, pady=(3, compact_pad_y))


    # khung chuc nang

    button_card = customtkinter.CTkFrame(input_card)
    button_card.grid(row=0, column=2, sticky="nsew", padx=(4, 0), pady=4)

    button_title_label = customtkinter.CTkLabel(button_card, text="Chức năng", anchor="w")
    button_title_label.pack(fill="x", padx=compact_pad_x, pady=(6, 2))

    button_inner_frame = customtkinter.CTkFrame(button_card)
    button_inner_frame.pack(fill="x", padx=compact_pad_x, pady=(0, compact_pad_y))

    button_inner_frame.grid_columnconfigure(0, weight=1)

    clear_button = customtkinter.CTkButton(button_inner_frame, text="Làm mới", command=clear_inputs)
    clear_button.grid(row=1, column=0, sticky="ew", padx=compact_pad_x, pady=(3, compact_pad_y))

    attack_button = customtkinter.CTkButton(button_inner_frame, text="Tấn công", command=run_attack)
    attack_button.grid(row=0, column=0, sticky="ew", padx=compact_pad_x, pady=(compact_pad_y, 3))


    content_frame = customtkinter.CTkFrame(attackrsa)
    content_frame.pack(fill="both", expand=True)
    content_frame.grid_columnconfigure(0, weight=6)
    content_frame.grid_columnconfigure(1, weight=4)
    content_frame.grid_rowconfigure(0, weight=1)

    # khung luy thua

    power_card = customtkinter.CTkFrame(content_frame)
    power_card.grid(row=0, column=0, sticky="nsew", padx=(0, 4), pady=0)

    power_title_label = customtkinter.CTkLabel(power_card, text="Lũy thừa modulo", anchor="w")
    power_title_label.pack(fill="x", padx=compact_pad_x, pady=(6, 2))

    modulus_info_frame = customtkinter.CTkFrame(power_card)
    modulus_info_frame.pack(fill="x", padx=compact_pad_x, pady=(0, compact_pad_y))

    modulus_info_frame.grid_columnconfigure(0, weight=0, minsize=96)
    modulus_info_frame.grid_columnconfigure(1, weight=1)

    modulus_label = customtkinter.CTkLabel(modulus_info_frame, text="Số modulus n:", anchor="w")
    modulus_label.grid(row=0, column=0, sticky="ew", padx=(compact_pad_x, 4), pady=compact_pad_y)

    modulus_value_label = customtkinter.CTkTextbox(modulus_info_frame, height=value_height)
    modulus_value_label.grid(row=0, column=1, sticky="ew", padx=(4, compact_pad_x), pady=compact_pad_y)

    power_detail_frame = customtkinter.CTkFrame(power_card)
    power_detail_frame.pack(fill="x", padx=compact_pad_x, pady=(0, compact_pad_y))

    power_detail_frame.grid_columnconfigure(0, weight=1)
    power_detail_frame.grid_columnconfigure(1, weight=1)


    # khung c1

    c1_power_card = customtkinter.CTkFrame(power_detail_frame)
    c1_power_card.grid(row=0, column=0, sticky="nsew", padx=(0, 4), pady=compact_pad_y)

    c1_title_label = customtkinter.CTkLabel(c1_power_card, text="Xử lý C1", anchor="w")
    c1_title_label.pack(fill="x", padx=compact_pad_x, pady=(6, 2))

    c1_table_frame = customtkinter.CTkFrame(c1_power_card)
    c1_table_frame.pack(fill="x", padx=compact_pad_x, pady=(0, compact_pad_y))

    c1_table_frame.grid_columnconfigure(0, weight=0, minsize=104)
    c1_table_frame.grid_columnconfigure(1, weight=1)

    c1_base_label = customtkinter.CTkLabel(c1_table_frame, text="Cơ số ban đầu", anchor="w")
    c1_base_label.grid(row=0, column=0, sticky="ew", padx=(compact_pad_x, 4), pady=3)
    c1_base_value_label = customtkinter.CTkTextbox(c1_table_frame, height=value_height)
    c1_base_value_label.grid(row=0, column=1, sticky="ew", padx=(4, compact_pad_x), pady=3)

    c1_exponent_label = customtkinter.CTkLabel(c1_table_frame, text="Số mũ ban đầu", anchor="w")
    c1_exponent_label.grid(row=1, column=0, sticky="ew", padx=(compact_pad_x, 4), pady=3)
    c1_exponent_value_label = customtkinter.CTkTextbox(c1_table_frame, height=small_value_height)
    c1_exponent_value_label.grid(row=1, column=1, sticky="ew", padx=(4, compact_pad_x), pady=3)

    c1_inverse_label = customtkinter.CTkLabel(c1_table_frame, text="Nghịch đảo", anchor="w")
    c1_inverse_label.grid(row=2, column=0, sticky="ew", padx=(compact_pad_x, 4), pady=3)
    c1_inverse_value_label = customtkinter.CTkTextbox(c1_table_frame, height=value_height)
    c1_inverse_value_label.grid(row=2, column=1, sticky="ew", padx=(4, compact_pad_x), pady=3)

    c1_result_label = customtkinter.CTkLabel(c1_table_frame, text="Kết quả", anchor="w")
    c1_result_label.grid(row=3, column=0, sticky="ew", padx=(compact_pad_x, 4), pady=3)
    c1_result_value_label = customtkinter.CTkTextbox(c1_table_frame, height=value_height)
    c1_result_value_label.grid(row=3, column=1, sticky="ew", padx=(4, compact_pad_x), pady=3)

    c1_time_label = customtkinter.CTkLabel(c1_table_frame, text="Thời gian xử lý", anchor="w")
    c1_time_label.grid(row=4, column=0, sticky="ew", padx=(compact_pad_x, 4), pady=(3, compact_pad_y))
    c1_time_value_label = customtkinter.CTkTextbox(c1_table_frame, height=small_value_height)
    c1_time_value_label.grid(row=4, column=1, sticky="ew", padx=(4, compact_pad_x), pady=(3, compact_pad_y))


    # khung c2

    c2_power_card = customtkinter.CTkFrame(power_detail_frame)
    c2_power_card.grid(row=0, column=1, sticky="nsew", padx=(4, 0), pady=compact_pad_y)

    c2_title_label = customtkinter.CTkLabel(c2_power_card,text="Xử lý C2", anchor="w")
    c2_title_label.pack(fill="x", padx=compact_pad_x, pady=(6, 2))

    c2_table_frame = customtkinter.CTkFrame(c2_power_card)
    c2_table_frame.pack(fill="x", padx=compact_pad_x, pady=(0, compact_pad_y))

    c2_table_frame.grid_columnconfigure(0, weight=0, minsize=104)
    c2_table_frame.grid_columnconfigure(1, weight=1)

    c2_base_label = customtkinter.CTkLabel(c2_table_frame, text="Cơ số ban đầu", anchor="w")
    c2_base_label.grid(row=0, column=0, sticky="ew", padx=(compact_pad_x, 4), pady=3)
    c2_base_value_label = customtkinter.CTkTextbox(c2_table_frame, height=value_height)
    c2_base_value_label.grid(row=0, column=1, sticky="ew", padx=(4, compact_pad_x), pady=3)

    c2_exponent_label = customtkinter.CTkLabel(c2_table_frame, text="Số mũ ban đầu", anchor="w")
    c2_exponent_label.grid(row=1, column=0, sticky="ew", padx=(compact_pad_x, 4), pady=3)
    c2_exponent_value_label = customtkinter.CTkTextbox(c2_table_frame, height=small_value_height)
    c2_exponent_value_label.grid(row=1, column=1, sticky="ew", padx=(4, compact_pad_x), pady=3)

    c2_inverse_label = customtkinter.CTkLabel(c2_table_frame, text="Nghịch đảo", anchor="w")
    c2_inverse_label.grid(row=2, column=0, sticky="ew", padx=(compact_pad_x, 4), pady=3)
    c2_inverse_value_label = customtkinter.CTkTextbox(c2_table_frame, height=value_height)
    c2_inverse_value_label.grid(row=2, column=1, sticky="ew", padx=(4, compact_pad_x), pady=3)

    c2_result_label = customtkinter.CTkLabel(c2_table_frame, text="Kết quả", anchor="w")
    c2_result_label.grid(row=3, column=0, sticky="ew", padx=(compact_pad_x, 4), pady=3)
    c2_result_value_label = customtkinter.CTkTextbox(c2_table_frame, height=value_height)
    c2_result_value_label.grid(row=3, column=1, sticky="ew", padx=(4, compact_pad_x), pady=3)

    c2_time_label = customtkinter.CTkLabel(c2_table_frame, text="Thời gian xử lý", anchor="w")
    c2_time_label.grid(row=4, column=0, sticky="ew", padx=(compact_pad_x, 4), pady=(3, compact_pad_y))
    c2_time_value_label = customtkinter.CTkTextbox(c2_table_frame, height=small_value_height)
    c2_time_value_label.grid(row=4, column=1, sticky="ew", padx=(4, compact_pad_x), pady=(3, compact_pad_y))


    final_mod_value_label = customtkinter.CTkTextbox(power_card, height=value_height)
    final_mod_value_label.pack(fill="x", padx=compact_pad_x, pady=(0, compact_pad_y))
    final_mod_value_label.insert("1.0", str("Kết quả mod: "))


    # khung ket qua

    result_card = customtkinter.CTkFrame(content_frame)
    result_card.grid(row=0, column=1, sticky="nsew", padx=(4, 0), pady=0)

    result_title_label = customtkinter.CTkLabel(result_card, text="Kết quả cuối cùng", anchor="w")
    result_title_label.pack(fill="x", padx=compact_pad_x, pady=(6, 2))

    result_table_frame = customtkinter.CTkFrame(result_card)
    result_table_frame.pack(fill="both", expand=True, padx=compact_pad_x, pady=(0, compact_pad_y))

    result_table_frame.grid_columnconfigure(0, weight=0, minsize=98)
    result_table_frame.grid_columnconfigure(1, weight=1)

    result_decimal_label = customtkinter.CTkLabel(result_table_frame, text="Decimal", anchor="w")
    result_decimal_label.grid(row=0, column=0, sticky="ew", padx=(compact_pad_x, 4), pady=3)

    result_decimal_value_label = customtkinter.CTkTextbox(result_table_frame, height=value_height)
    result_decimal_value_label.grid(row=0, column=1, sticky="ew", padx=(4, compact_pad_x), pady=3)

    result_text_label = customtkinter.CTkLabel(result_table_frame, text="Text UTF-8", anchor="w")
    result_text_label.grid(row=1, column=0, sticky="ew", padx=(compact_pad_x, 4), pady=3)

    result_text_value_label = customtkinter.CTkTextbox(result_table_frame, height=value_height)
    result_text_value_label.grid(row=1, column=1, sticky="ew", padx=(4, compact_pad_x), pady=3)

    result_hex_label = customtkinter.CTkLabel(result_table_frame, text="Hex", anchor="w")
    result_hex_label.grid(row=2, column=0, sticky="ew", padx=(compact_pad_x, 4), pady=3)

    result_hex_value_label = customtkinter.CTkTextbox(result_table_frame, height=value_height)
    result_hex_value_label.grid(row=2, column=1, sticky="ew", padx=(4, compact_pad_x), pady=3)

    result_binary_label = customtkinter.CTkLabel(result_table_frame, text="Binary", anchor="w")
    result_binary_label.grid(row=3, column=0, sticky="ew", padx=(compact_pad_x, 4), pady=3)

    result_binary_value_label = customtkinter.CTkTextbox(result_table_frame, height=value_height)
    result_binary_value_label.grid(row=3, column=1, sticky="ew", padx=(4, compact_pad_x), pady=3)

    result_octal_label = customtkinter.CTkLabel(result_table_frame, text="Octal", anchor="w")
    result_octal_label.grid(row=4, column=0, sticky="ew", padx=(compact_pad_x, 4), pady=3)

    result_octal_value_label = customtkinter.CTkTextbox(result_table_frame, height=value_height)
    result_octal_value_label.grid(row=4, column=1, sticky="ew", padx=(4, compact_pad_x), pady=3)

    result_time_label = customtkinter.CTkLabel(result_table_frame, text="Tổng thời gian tấn công", anchor="w")
    result_time_label.grid(row=5, column=0, sticky="ew", padx=(compact_pad_x, 4), pady=(3, compact_pad_y))

    result_time_value_label = customtkinter.CTkTextbox(result_table_frame, height=value_height)
    result_time_value_label.grid(row=5, column=1, sticky="ew", padx=(4, compact_pad_x), pady=(3, compact_pad_y))

    modulus_label.configure(text="Modulus n", width=92)

    c1_base_label.configure(text="Cơ số", width=96)
    c1_exponent_label.configure(text="Số mũ", width=96)
    c1_inverse_label.configure(width=96)
    c1_result_label.configure(width=96)
    c1_time_label.configure(text="Thời gian", width=96)

    c2_base_label.configure(text="Cơ số", width=96)
    c2_exponent_label.configure(text="Số mũ", width=96)
    c2_inverse_label.configure(width=96)
    c2_result_label.configure(width=96)
    c2_time_label.configure(text="Thời gian", width=96)

    result_decimal_label.configure(width=94)
    result_text_label.configure(width=94)
    result_hex_label.configure(width=94)
    result_binary_label.configure(width=94)
    result_octal_label.configure(width=94)
    result_time_label.configure(text="Tổng thời gian", width=94)

    # khung loi
    error_card = customtkinter.CTkFrame(attackrsa)
    error_card.pack(fill="x", pady=(section_gap, 0))

    error_title_label = customtkinter.CTkLabel(error_card, text="Trạng thái", anchor="w")
    error_title_label.pack(fill="x", padx=compact_pad_x, pady=(6, 2))

    error_value_label = customtkinter.CTkTextbox(error_card, height=100)
    error_value_label.pack(fill="x", padx=compact_pad_x, pady=(0, compact_pad_y))

