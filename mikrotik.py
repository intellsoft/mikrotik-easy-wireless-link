import tkinter as tk
from tkinter import ttk, messagebox, Menu
import random
import string
import re
import requests
import webbrowser
from ttkthemes import ThemedTk # اضافه کردن این خط

# --- Global Variables ---
SOFTWARE_VERSION = "0.1"
GITHUB_VERSION_URL = "https://raw.githubusercontent.com/intellsoft/mikrotik-easy-wireless-link/main/VERSION.txt"
GITHUB_REPO_URL = "https://github.com/intellsoft/mikrotik-easy-wireless-link"
WEBSITE_URL = "https://intellsoft.ir/"

# --- Functions ---
def generate_password(length=12):
    """Generates a random password."""
    characters = string.ascii_letters + string.digits + "!@#$%^&*()"
    return ''.join(random.choice(characters) for _ in range(length))

def generate_script():
    """Generates the MikroTik script based on user inputs."""
    mode = mode_var.get()
    password = password_entry.get()
    identity = identity_entry.get()
    ip = ip_entry.get()
    ssid = ssid_entry.get()
    wifi_pass = wifi_pass_entry.get()
    country = country_var.get()
    channel_width = channel_width_var.get()
    wireless_protocol = protocol_var.get()
    frequency = frequency_var.get()

    # Input validation
    if not all([password, identity, ip, ssid, wifi_pass, country, channel_width, frequency]):
        status_label.config(text="لطفاً همه فیلدها را پر کنید.", foreground="red")
        return

    script = ""
    if mode == "AP (یک نقطه به چند نقطه)":
        script = f"""/interface bridge
add name=bridge1
/interface wireless
set [ find default-name=wlan1 ] band=5ghz-a/n channel-width={channel_width} \\
    country={country} disabled=no frequency={frequency} frequency-mode=superchannel \\
    mode=ap-bridge nv2-preshared-key="{wifi_pass}" nv2-security=enabled ssid="{ssid}" \\
    wireless-protocol={wireless_protocol}
/interface wireless security-profiles
set [ find default=yes ] authentication-types=wpa2-psk mode=dynamic-keys \\
    supplicant-identity=MikroTik wpa2-pre-shared-key="{wifi_pass}"
/ip hotspot profile
set [ find default=yes ] html-directory=hotspot
/interface bridge port
add bridge=bridge1 interface=wlan1
add bridge=bridge1 interface=ether1
/ip neighbor discovery-settings
set discover-interface-list=!dynamic
/ip address
add address={ip}/24 interface=bridge1 network={ip.rsplit('.',1)[0]}.0
/system identity
set name={identity}
/user set admin password="{password}"
"""
    elif mode == "AP (یک نقطه به یک نقطه)":
        script = f"""/interface bridge
add name=bridge1
/interface wireless
set [ find default-name=wlan1 ] band=5ghz-a/n channel-width={channel_width} \\
    country={country} disabled=no frequency={frequency} frequency-mode=superchannel \\
    mode=bridge nv2-preshared-key="{wifi_pass}" nv2-security=enabled ssid="{ssid}" \\
    wireless-protocol={wireless_protocol}
/interface wireless security-profiles
set [ find default=yes ] authentication-types=wpa2-psk mode=dynamic-keys \\
    supplicant-identity=MikroTik wpa2-pre-shared-key="{wifi_pass}"
/ip hotspot profile
set [ find default=yes ] html-directory=hotspot
/interface bridge port
add bridge=bridge1 interface=wlan1
add bridge=bridge1 interface=ether1
/ip neighbor discovery-settings
set discover-interface-list=!dynamic
/ip address
add address={ip}/24 interface=bridge1 network={ip.rsplit('.',1)[0]}.0
/system identity
set name={identity}
/user set admin password="{password}"
"""
    else:  # Station mode
        script = f"""/interface bridge
add name=bridge1
/interface wireless
set [ find default-name=wlan1 ] band=5ghz-a/n channel-width={channel_width} \\
    country={country} disabled=no frequency={frequency} frequency-mode=superchannel \\
    mode=station-bridge nv2-preshared-key="{wifi_pass}" nv2-security=enabled \\
    scan-list={frequency} ssid="{ssid}" wireless-protocol={wireless_protocol}
/interface wireless security-profiles
set [ find default=yes ] authentication-types=wpa2-psk mode=dynamic-keys \\
    supplicant-identity=MikroTik wpa2-pre-shared-key="{wifi_pass}"
/ip hotspot profile
set [ find default=yes ] html-directory=hotspot
/interface bridge port
add bridge=bridge1 interface=wlan1
add bridge=bridge1 interface=ether1
/ip neighbor discovery-settings
set discover-interface-list=!dynamic
/ip address
add address={ip}/24 interface=bridge1 network={ip.rsplit('.',1)[0]}.0
/system identity
set name={identity}
/user set admin password="{password}"
"""
    
    # Clean identity and IP for filename
    clean_identity = re.sub(r'[\\/:*?"<>|]', '', identity)
    clean_ip = re.sub(r'[\\/:*?"<>|]', '', ip).replace('.', '_')

    file_name = f"mikrotik_script_{clean_identity}_{clean_ip}.rsc"

    try:
        with open(file_name, "w", encoding="utf-8") as file:
            file.write(script)
        output_text.delete(1.0, tk.END)
        output_text.insert(tk.END, script)
        status_label.config(text=f"اسکریپت با موفقیت با نام '{file_name}' ایجاد و ذخیره شد.", foreground="green")
    except Exception as e:
        status_label.config(text=f"خطا در ذخیره فایل: {e}", foreground="red")

def copy_to_clipboard():
    """Copies the generated script to the clipboard."""
    script = output_text.get(1.0, tk.END)
    root.clipboard_clear()
    root.clipboard_append(script)
    status_label.config(text="محتوای اسکریپت به کلیپ‌بورد کپی شد.", foreground="green")

def create_password_field(parent, label_text, row):
    """Creates a label, entry, and password generation button."""
    label = ttk.Label(parent, text=label_text)
    label.grid(row=row, column=0, padx=5, pady=5, sticky="e")

    entry = ttk.Entry(parent, width=40, show="*", style="TEntry")
    entry.grid(row=row, column=1, padx=5, pady=5, sticky="ew")

    def insert_password():
        entry.delete(0, tk.END)
        entry.insert(0, generate_password())

    gen_button = ttk.Button(parent, text="تولید رمز", command=insert_password, style="TButton")
    gen_button.grid(row=row, column=2, padx=5, pady=5)

    return entry

def add_form_row(parent, label_text, row):
    """Creates a label and an entry field."""
    label = ttk.Label(parent, text=label_text)
    label.grid(row=row, column=0, padx=5, pady=5, sticky="e")

    entry = ttk.Entry(parent, width=40, style="TEntry")
    entry.grid(row=row, column=1, padx=5, pady=5, sticky="ew")

    return entry

def add_dropdown_row(parent, label_text, options, row, default_value=None):
    """Creates a label and a dropdown (Combobox) field."""
    label = ttk.Label(parent, text=label_text)
    label.grid(row=row, column=0, padx=5, pady=5, sticky="e")
    
    var = tk.StringVar()
    if default_value:
        var.set(default_value)
    else:
        var.set(options[0])
        
    dropdown = ttk.Combobox(parent, textvariable=var, values=options, width=37, state="readonly", style="TCombobox")
    dropdown.grid(row=row, column=1, padx=5, pady=5, sticky="ew")
    
    return var

def show_about():
    """Displays the 'About' window with software information and links."""
    about_window = tk.Toplevel(root)
    about_window.title("درباره ابزار تنظیم آسان رادیو میکروتیک")
    about_window.transient(root) # Make About window appear on top of the main window
    about_window.grab_set() # Disable interaction with the main window until About is closed
    about_window.resizable(False, False) # Make About window not resizable

    about_frame = ttk.Frame(about_window, padding="15")
    about_frame.pack(fill="both", expand=True)

    ttk.Label(about_frame, text="نام نرم افزار: ابزار تنظیم آسان رادیو میکروتیک", font=("Tahoma", 11, "bold")).pack(pady=5)
    ttk.Label(about_frame, text="برنامه نویس: محمدعلی عباسپور", font=("Tahoma", 10)).pack(pady=2)
    ttk.Label(about_frame, text=f"نسخه نرم افزار: {SOFTWARE_VERSION}", font=("Tahoma", 10)).pack(pady=2)

    # Website Link
    website_label = ttk.Label(about_frame, text=f"وب سایت: {WEBSITE_URL}", font=("Tahoma", 10), foreground="blue", cursor="hand2")
    website_label.pack(pady=2)
    website_label.bind("<Button-1>", lambda e: webbrowser.open_new(WEBSITE_URL))

    # GitHub Project Link
    github_label = ttk.Label(about_frame, text=f"پروژه در گیت‌هاب: {GITHUB_REPO_URL}", font=("Tahoma", 10), foreground="blue", cursor="hand2")
    github_label.pack(pady=2)
    github_label.bind("<Button-1>", lambda e: webbrowser.open_new(GITHUB_REPO_URL))

    ttk.Button(about_frame, text="بستن", command=about_window.destroy, style="TButton").pack(pady=10)

def check_for_updates():
    """Checks for a new version of the software from GitHub and displays a message in the UI."""
    try:
        response = requests.get(GITHUB_VERSION_URL, timeout=5)
        response.raise_for_status() # Raise an HTTPError for bad responses (4xx or 5xx)
        latest_version = response.text.strip()

        if latest_version > SOFTWARE_VERSION:
            update_message = f"نسخه جدید ({latest_version}) موجود است! برای دانلود کلیک کنید."
            update_label.config(text=update_message, foreground="orange", cursor="hand2")
            update_label.bind("<Button-1>", lambda e: webbrowser.open_new(GITHUB_REPO_URL))
            update_label.pack(pady=5) # اطمینان حاصل کنید که این لیبل قابل مشاهده است
        else:
            # اگر آخرین نسخه باشد، پیام را پاک کنید (اگر قبلاً نمایش داده شده باشد)
            update_label.pack_forget() # یا update_label.config(text="")
    except requests.exceptions.RequestException as e:
        # در صورت خطا، پیام خطا را در نوار وضعیت اصلی نمایش دهید
        status_label.config(text=f"خطا در بررسی آپدیت: {e}. اینترنت را بررسی کنید.", foreground="red")
        update_label.pack_forget() # مطمئن شوید پیام آپدیت قدیمی نیست
    except Exception as e:
        status_label.config(text=f"خطای غیرمنتظره در بررسی آپدیت: {e}", foreground="red")
        update_label.pack_forget()


def create_menu():
    """Creates the application's menu bar."""
    menubar = Menu(root)
    root.config(menu=menubar)

    # File Menu
    file_menu = Menu(menubar, tearoff=0)
    menubar.add_cascade(label="File", menu=file_menu)
    file_menu.add_command(label="Exit", command=root.quit) # Use root.quit to exit the application

    # Help Menu
    help_menu = Menu(menubar, tearoff=0)
    menubar.add_cascade(label="Help", menu=help_menu)
    help_menu.add_command(label="About", command=show_about)

# --- Main Window Setup ---
# تغییر اصلی: استفاده از ThemedTk به جای tk.Tk و انتخاب تم 'vista'
root = ThemedTk(theme="vista") # برای شبیه سازی ویندوز جدید از تم "vista" استفاده کنید.
root.title("تولید اسکریپت MikroTik")
root.state('zoomed') # Open window maximized

# Apply ttk style (already handled by ThemedTk theme)
style = ttk.Style(root)
# نیازی به style.theme_use('clam') نیست وقتی ThemedTk استفاده می شود.

# Configure fonts for widgets
style.configure("TLabel", font=("Tahoma", 10))
style.configure("TButton", font=("Tahoma", 10, "bold"))
style.configure("TEntry", font=("Tahoma", 10))
style.configure("TCombobox", font=("Tahoma", 10))
style.configure("TLabelframe.Label", font=("Tahoma", 11, "bold"))

# فریم اصلی برای نگه داشتن همه عناصر و مرکزیت آنها
main_frame = ttk.Frame(root, padding="10 10 10 10")
main_frame.pack(expand=True, fill="both", padx=20, pady=20)

# لیبل برای نمایش پیام آپدیت در بالای برنامه
# این لیبل را در اینجا تعریف می‌کنیم تا در تابع check_for_updates قابل دسترسی باشد.
update_label = ttk.Label(main_frame, text="", font=("Tahoma", 10, "bold"), foreground="orange")
# این خط 'pack' را فعلاً حذف می‌کنیم، فقط زمانی که آپدیت موجود بود، آن را 'pack' می‌کنیم.
# update_label.pack(pady=5) # این خط را به داخل تابع check_for_updates منتقل می کنیم

# Define mode_var and modes before using them in mode_combo
mode_var = tk.StringVar(value="AP (یک نقطه به چند نقطه)")
modes = [
    "AP (یک نقطه به چند نقطه)",
    "AP (یک نقطه به یک نقطه)",
    "استیشن"
]

# Radio Mode Selection
mode_frame = ttk.LabelFrame(main_frame, text="انتخاب حالت رادیو", padding="10 10 10 10")
mode_frame.pack(padx=10, pady=10, fill="x")

# Use grid for better internal layout control of mode_frame
mode_frame.columnconfigure(1, weight=1) # Column 1 (combobox) expands

ttk.Label(mode_frame, text="حالت:", style="TLabel").grid(row=0, column=0, padx=5, pady=5, sticky="w")
mode_combo = ttk.Combobox(mode_frame, textvariable=mode_var, values=modes, width=40, state="readonly", style="TCombobox")
mode_combo.grid(row=0, column=1, padx=5, pady=5, sticky="ew")


# Input Form
form_frame = ttk.LabelFrame(main_frame, text="اطلاعات تنظیمات", padding="10 10 10 10")
form_frame.pack(padx=10, pady=10, fill="x")

# Configure form columns to expand
form_frame.columnconfigure(1, weight=1) # Column 1 (entries) expands

password_entry = create_password_field(form_frame, "رمز عبور جدید:", 0)
identity_entry = add_form_row(form_frame, "نام رادیو (Identity):", 1)
ip_entry = add_form_row(form_frame, "آدرس IP (مثال: 192.168.1.155):", 2)
ssid_entry = add_form_row(form_frame, "نام وایرلس (SSID):", 3)
wifi_pass_entry = create_password_field(form_frame, "رمز وایرلس:", 4)

country_var = add_dropdown_row(form_frame, "کشور:", ["azerbaijan", "iran", "germany", "usa"], 5, "azerbaijan")
channel_width_var = add_dropdown_row(form_frame, "پهنای کانال:", ["20/40mhz-Ce", "20mhz", "40mhz", "80mhz"], 6, "20/40mhz-Ce")
protocol_var = add_dropdown_row(form_frame, "پروتکل وایرلس:", ["nv2", "802.11"], 7, "nv2")

frequencies = [str(freq) for freq in range(4920, 6085, 5)]
frequency_var = add_dropdown_row(form_frame, "فرکانس (MHz):", frequencies, 8, "5500")

# Generate Script Button
generate_button = ttk.Button(main_frame, text="تولید اسکریپت", command=generate_script, style="TButton")
generate_button.pack(pady=10)

# Status Message Display (for errors or success messages)
status_label = ttk.Label(main_frame, text="", foreground="green", style="TLabel")
status_label.pack()

# Script Output Display
output_frame = ttk.LabelFrame(main_frame, text="اسکریپت تولید شده", padding="10 10 10 10")
output_frame.pack(padx=10, pady=10, fill="both", expand=True)

output_text = tk.Text(output_frame, wrap="word", font=("Courier New", 10), height=15, relief="solid", borderwidth=1)
output_text.pack(padx=5, pady=5, fill="both", expand=True)

# Copy Button
copy_button = ttk.Button(main_frame, text="کپی به کلیپ‌بورد", command=copy_to_clipboard, style="TButton")
copy_button.pack(pady=10)

# Create the menu bar
create_menu()

# Check for updates when the application starts
check_for_updates()

root.mainloop()