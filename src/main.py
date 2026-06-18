import customtkinter

from Display.attackui import build_attack_tab
from Display.cipherui import build_cipher_tab


customtkinter.set_appearance_mode("system")
customtkinter.set_default_color_theme("blue")

app = customtkinter.CTk()
app.title("ATTACK RSA MODULUS")
app.geometry("1000x700")

main_scroll_frame = customtkinter.CTkScrollableFrame(app)
main_scroll_frame.pack(fill="both", expand=True, padx=12, pady=12)

tab_view = customtkinter.CTkTabview(main_scroll_frame)
tab_view.pack(fill="both", expand=True, pady=10)

attack_tab = tab_view.add("Attack")
cipher_tab = tab_view.add("Cipher")
system_tab = tab_view.add("Color")

build_attack_tab(attack_tab)
build_cipher_tab(cipher_tab)

is_dark = False

def setting_color_theme():
    global is_dark

    if is_dark:
        customtkinter.set_appearance_mode("light")
        button_change_color_theme.configure(text="Chế độ tối")
        is_dark = False
    else:
        customtkinter.set_appearance_mode("dark")
        button_change_color_theme.configure(text="Chế độ sáng")
        is_dark = True

button_change_color_theme = customtkinter.CTkButton(system_tab, text="Chế độ tối", command=setting_color_theme)
button_change_color_theme.pack(pady=50)



app.mainloop()