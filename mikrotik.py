import tkinter as tk
from tkinter import ttk
import random
import string

def generate_password(length=12):
    characters = string.ascii_letters + string.digits + "!@#$%^&*()"
    return ''.join(random.choice(characters) for _ in range(length))

def generate_script():
    mode = mode_var.get()
    password = password_entry.get()
    identity = identity_entry.get()
    ip = ip_entry.get()
    ssid = ssid_entry.get()
    wifi_pass = wifi_pass_entry.get()

    if not all([password, identity, ip, ssid, wifi_pass]):
        status_label.config(text="لطفاً همه فیلدها را پر کنید.", foreground="red")
        return

    if mode == "AP":
        script = f"""
/user set admin password="{password}"
/system identity set name="{identity}"
/ip address add address={ip}/24 interface=bridge1
/interface bridge add name=bridge1
/interface wireless set [ find default-name=wlan1 ] disabled=no \\
    ssid="{ssid}" mode=ap-bridge frequency=2412 band=2ghz-b/g/n \\
    security-profile=sec-wpa2
/interface wireless security-profiles add name=sec-wpa2 \\
    authentication-types=wpa2-psk wpa2-pre-shared-key="{wifi_pass}" \\
    unicast-ciphers=aes-ccm group-ciphers=aes-ccm
/interface bridge port add bridge=bridge1 interface=wlan1
"""
    else:
        script = f"""
/user set admin password="{password}"
/system identity set name="{identity}"
/ip address add address={ip}/24 interface=ether1
/interface wireless set [ find default-name=wlan1 ] disabled=no \\
    ssid="{ssid}" mode=station-bridge frequency=2412 band=2ghz-b/g/n \\
    security-profile=sec-wpa2
/interface wireless security-profiles add name=sec-wpa2 \\
    authentication-types=wpa2-psk wpa2-pre-shared-key="{wifi_pass}" \\
    unicast-ciphers=aes-ccm group-ciphers=aes-ccm
"""

    try:
        with open("mikrotik_script.rsc", "w", encoding="utf-8") as file:
            file.write(script)
        output_text.delete(1.0, tk.END)
        output_text.insert(tk.END, script)
        status_label.config(text="اسکریپت با موفقیت ایجاد و ذخیره شد.", foreground="green")
    except Exception as e:
        status_label.config(text=f"خطا در ذخیره فایل: {e}", foreground="red")

def copy_to_clipboard():
    script = output_text.get(1.0, tk.END)
    root.clipboard_clear()
    root.clipboard_append(script)
    status_label.config(text="محتوای اسکریپت به کلیپ‌بورد کپی شد.", foreground="green")

def create_password_field(parent, label_text, row):
    label = ttk.Label(parent, text=label_text)
    label.grid(row=row, column=0, padx=5, pady=5, sticky="e")

    entry = ttk.Entry(parent, width=40)
    entry.grid(row=row, column=1, padx=5, pady=5, sticky="w")

    def insert_password():
        entry.delete(0, tk.END)
        entry.insert(0, generate_password())

    gen_button = ttk.Button(parent, text="تولید رمز", command=insert_password)
    gen_button.grid(row=row, column=2, padx=5, pady=5)

    return entry

def add_form_row(parent, label_text, row):
    label = ttk.Label(parent, text=label_text)
    label.grid(row=row, column=0, padx=5, pady=5, sticky="e")

    entry = ttk.Entry(parent, width=40)
    entry.grid(row=row, column=1, padx=5, pady=5, sticky="w")

    return entry

# ایجاد پنجره اصلی
root = tk.Tk()
root.title("تولید اسکریپت MikroTik")
root.state('zoomed')  # باز کردن پنجره در حالت حداکثر

# انتخاب حالت
mode_var = tk.StringVar(value="AP")
mode_frame = ttk.LabelFrame(root, text="انتخاب حالت رادیو")
mode_frame.pack(padx=10, pady=10, fill="x")

ap_radio = ttk.Radiobutton(mode_frame, text="اکسس پوینت", variable=mode_var, value="AP")
ap_radio.pack(side="right", padx=5, pady=5)

station_radio = ttk.Radiobutton(mode_frame, text="استیشن", variable=mode_var, value="Station")
station_radio.pack(side="right", padx=5, pady=5)

# فرم ورودی
form_frame = ttk.LabelFrame(root, text="اطلاعات تنظیمات")
form_frame.pack(padx=10, pady=10, fill="x")

password_entry = create_password_field(form_frame, "رمز عبور جدید:", 0)
identity_entry = add_form_row(form_frame, "نام رادیو (Identity):", 1)
ip_entry = add_form_row(form_frame, "آدرس IP:", 2)
ssid_entry = add_form_row(form_frame, "نام وایرلس (SSID):", 3)
wifi_pass_entry = create_password_field(form_frame, "رمز وایرلس:", 4)

# دکمه تولید اسکریپت
generate_button = ttk.Button(root, text="تولید اسکریپت", command=generate_script)
generate_button.pack(pady=10)

# نمایش پیام وضعیت
status_label = ttk.Label(root, text="", foreground="green")
status_label.pack()

# نمایش اسکریپت
output_frame = ttk.LabelFrame(root, text="اسکریپت تولید شده")
output_frame.pack(padx=10, pady=10, fill="both", expand=True)

output_text = tk.Text(output_frame, wrap="word")
output_text.pack(padx=5, pady=5, fill="both", expand=True)

# دکمه کپی
copy_button = ttk.Button(root, text="کپی به کلیپ‌بورد", command=copy_to_clipboard)
copy_button.pack(pady=10)

root.mainloop()
