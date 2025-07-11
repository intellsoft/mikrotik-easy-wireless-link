
# ابزار تنظیم آسان رادیو میکروتیک

## 🚀 معرفی

**آیا از پیچیدگی تنظیمات رادیوهای میکروتیک خسته شده‌اید؟** این ابزار ساده و کاربرپسند به شما کمک می‌کند تا به سرعت و بدون نیاز به دانش عمیق در مورد دستورات میکروتیک، اسکریپت‌های لازم برای راه‌اندازی لینک‌های وایرلس خود را تولید کنید. چه بخواهید یک نقطه دسترسی (AP) برای اتصال چندین کلاینت ایجاد کنید، چه یک لینک نقطه به نقطه، یا یک رادیو استیشن، این برنامه کار شما را آسان می‌کند\!

این ابزار با یک رابط کاربری گرافیکی (GUI) ساده، فرآیند تولید اسکریپت‌های RouterOS را برای شما به یک تجربه لذت‌بخش و بی‌دردسر تبدیل می‌کند.

![mikrotik radio wireless easy config tools](https://github.com/intellsoft/mikrotik-easy-wireless-link/blob/main/%D8%A7%D8%A8%D8%B2%D8%A7%D8%B1%20%D8%AA%D9%86%D8%B8%DB%8C%D9%85%20%D8%A2%D8%B3%D8%A7%D9%86%20%D8%B1%D8%A7%D8%AF%DB%8C%D9%88%20%D9%85%DB%8C%DA%A9%D8%B1%D9%88%D8%AA%DB%8C%DA%A9.JPG)

## ✨ ویژگی‌ها

  * **رابط کاربری گرافیکی آسان:** بدون نیاز به تایپ دستورات پیچیده.
  * **پشتیبانی از سه حالت اصلی:**
      * **AP (یک نقطه به چند نقطه):** برای شبکه‌های وایرلس عمومی.
      * **AP (یک نقطه به یک نقطه):** برای لینک‌های اختصاصی.
      * **استیشن (Station):** برای کلاینت‌هایی که به AP متصل می‌شوند.
  * **تولید خودکار رمز عبور:** امکان تولید رمزهای عبور قوی و تصادفی برای Mikrotik و وایرلس.
  * **قابلیت تنظیم پارامترهای کلیدی:** شامل نام رادیو (Identity)، آدرس IP، نام وایرلس (SSID)، رمز وایرلس، کشور، پهنای کانال، پروتکل وایرلس (nv2 یا 802.11) و فرکانس.
  * **ذخیره خودکار اسکریپت:** اسکریپت تولید شده در یک فایل `.rsc` (MikroTik RouterOS Script) در کنار برنامه ذخیره می‌شود.
  * **کپی آسان:** یک دکمه برای کپی کردن کل اسکریپت به کلیپ‌بورد برای استفاده سریع.
  * **بررسی به‌روزرسانی خودکار:** برنامه به صورت خودکار بررسی می‌کند که آیا نسخه جدیدی در دسترس است یا خیر.
  * **سازگار با Windows:** طراحی شده با `ttkthemes` برای ظاهری مدرن و بومی در ویندوز.

## 🛠️ چگونه استفاده کنیم؟

استفاده از این ابزار بسیار ساده است:

1.  **اجرای برنامه:** فایل `mikrotik.py` را اجرا کنید. (اگر Python را نصب کرده‌اید، می‌توانید مستقیماً فایل را باز کنید.)
2.  **انتخاب حالت رادیو:**
      * **AP (یک نقطه به چند نقطه):** اگر می‌خواهید رادیوی شما به عنوان یک Access Point برای اتصال چندین دستگاه عمل کند.
      * **AP (یک نقطه به یک نقطه):** اگر قصد دارید یک لینک اختصاصی بین دو رادیو (مثلاً برای اتصال دو ساختمان) برقرار کنید.
      * **استیشن:** اگر رادیوی شما قرار است به یک Access Point موجود متصل شود.
3.  **پر کردن فیلدها:**
      * **رمز عبور جدید:** رمز عبوری که برای کاربر `admin` میکروتیک تنظیم می‌شود. می‌توانید از دکمه "تولید رمز" استفاده کنید.
      * **نام رادیو (Identity):** نامی که برای شناسایی رادیو در شبکه میکروتیک شما استفاده می‌شود.
      * **آدرس IP:** آدرس IP که به رادیو اختصاص داده می‌شود (مثال: `192.168.1.155`).
      * **نام وایرلس (SSID):** نام شبکه‌ی وایرلس شما (نامی که دستگاه‌های دیگر آن را می‌بینند).
      * **رمز وایرلس:** رمز عبور برای اتصال به شبکه‌ی وایرلس. می‌توانید از دکمه "تولید رمز" استفاده کنید.
      * **کشور:** انتخاب کشور برای مطابقت با قوانین فرکانسی محلی.
      * **پهنای کانال:** پهنای باند وایرلس (مثلاً `20/40mhz-Ce`).
      * **پروتکل وایرلس:** `nv2` (پیشنهاد شده برای لینک‌های PtP/PtMP میکروتیک) یا `802.11`.
      * **فرکانس (MHz):** فرکانس کاری رادیو (مثلاً `5500`).
4.  **تولید اسکریپت:** پس از پر کردن تمام فیلدها، روی دکمه "تولید اسکریپت" کلیک کنید.
5.  **ذخیره و کپی:** اسکریپت در بخش "اسکریپت تولید شده" نمایش داده می‌شود و به صورت خودکار در یک فایل `.rsc` با نامی مانند `mikrotik_script_نام‌رادیو_آدرس‌IP.rsc` در کنار برنامه ذخیره می‌گردد. همچنین می‌توانید با دکمه "کپی به کلیپ‌بورد" آن را مستقیماً کپی کنید.

## 📄 اسکریپت تولید شده (کمی فنی‌تر)

اسکریپت تولید شده شامل دستوراتی برای:

  * ایجاد یک بریج (Bridge) برای ترکیب رابط‌های شبکه (وایرلس و اترنت).
  * تنظیمات رابط وایرلس شامل باند، پهنای کانال، کشور، فرکانس، حالت کاری (AP/Station)، SSID و امنیت NV2.
  * پروفایل‌های امنیتی وایرلس (WPA2-PSK).
  * افزودن رابط‌های `wlan1` و `ether1` به بریج.
  * غیرفعال کردن کشف همسایه برای امنیت بیشتر.
  * تنظیم آدرس IP برای بریج.
  * تنظیم هویت سیستمی رادیو.
  * تغییر رمز عبور کاربر `admin`.

## ⚙️ نیازمندی‌ها

  * Python 3.x
  * کتابخانه‌های Python (به صورت خودکار با pip نصب می‌شوند):
      * `tkinter` (معمولاً با پایتون نصب می‌شود)
      * `ttkthemes`
      * `requests`

## 🚀 نصب

1.  **نصب Python:** اگر Python را ندارید، آن را از [python.org](https://www.python.org/downloads/) دانلود و نصب کنید.
2.  **دانلود پروژه:** این مخزن را به کامپیوتر خود کلون (clone) کنید یا فایل `mikrotik.py` را دانلود کنید:
    ```bash
    git clone https://github.com/intellsoft/mikrotik-easy-wireless-link.git
    cd mikrotik-easy-wireless-link
    ```
3.  **نصب وابستگی‌ها:** ترمینال یا Command Prompt را باز کرده و به پوشه پروژه بروید، سپس دستور زیر را اجرا کنید:
    ```bash
    pip install ttkthemes requests
    ```
4.  **اجرای برنامه:**
    ```bash
    python mikrotik.py
    ```

## 👨‍💻 درباره توسعه‌دهنده

این پروژه توسط [محمدعلی عباسپور](https://intellsoft.ir/) توسعه یافته است.

  * **وب‌سایت:** [intellsoft.ir](https://intellsoft.ir/)
  * **گیت‌هاب:** [intellsoft](https://github.com/intellsoft)

## 📄 مجوز

این پروژه تحت مجوز [MIT License](https://www.google.com/search?q=LICENSE) منتشر شده است.

-----

# MikroTik Easy Wireless Link Configuration Tool

## 🚀 Introduction

**Are you tired of the complexities of MikroTik radio configurations?** This simple and user-friendly tool helps you quickly generate the necessary scripts for setting up your wireless links without requiring deep knowledge of MikroTik commands. Whether you want to create an Access Point (AP) for multiple clients, a point-to-point link, or a station radio, this application makes your work easy\!

This tool, with its straightforward Graphical User Interface (GUI), transforms the process of generating RouterOS scripts into an enjoyable and hassle-free experience.

## ✨ Features

  * **Easy Graphical User Interface:** No need to type complex commands.
  * **Supports Three Main Modes:**
      * **AP (Point-to-Multipoint):** For general wireless networks.
      * **AP (Point-to-Point):** For dedicated links.
      * **Station:** For clients connecting to an existing AP.
  * **Automatic Password Generation:** Ability to generate strong, random passwords for MikroTik admin and wireless security.
  * **Configurable Key Parameters:** Includes radio name (Identity), IP address, wireless name (SSID), Wi-Fi password, country, channel width, wireless protocol (nv2 or 802.11), and frequency.
  * **Automatic Script Saving:** The generated script is saved to an `.rsc` (MikroTik RouterOS Script) file next to the application.
  * **Easy Copy:** A button to copy the entire script to the clipboard for quick use.
  * **Automatic Update Check:** The application automatically checks if a new version is available.
  * **Windows Compatible:** Designed with `ttkthemes` for a modern and native look on Windows.

## 🛠️ How to Use?

Using this tool is very simple:

1.  **Run the Application:** Execute the `mikrotik.py` file. (If you have Python installed, you can simply open the file.)
2.  **Select Radio Mode:**
      * **AP (Point-to-Multipoint):** If you want your radio to act as an Access Point for multiple devices.
      * **AP (Point-to-Point):** If you intend to establish a dedicated link between two radios (e.g., connecting two buildings).
      * **Station:** If your radio is going to connect to an existing Access Point.
3.  **Fill in the Fields:**
      * **New Password:** The password set for the MikroTik `admin` user. You can use the "Generate Password" button.
      * **Radio Name (Identity):** The name used to identify the radio in your MikroTik network.
      * **IP Address:** The IP address assigned to the radio (e.g., `192.168.1.155`).
      * **Wireless Name (SSID):** The name of your wireless network (the name other devices will see).
      * **Wi-Fi Password:** The password for connecting to the wireless network. You can use the "Generate Password" button.
      * **Country:** Select the country to comply with local frequency regulations.
      * **Channel Width:** The wireless bandwidth (e.g., `20/40mhz-Ce`).
      * **Wireless Protocol:** `nv2` (recommended for MikroTik PtP/PtMP links) or `802.11`.
      * **Frequency (MHz):** The operating frequency of the radio (e.g., `5500`).
4.  **Generate Script:** After filling all fields, click the "Generate Script" button.
5.  **Save and Copy:** The script will be displayed in the "Generated Script" section and automatically saved to an `.rsc` file with a name like `mikrotik_script_radio-name_ip-address.rsc` next to the application. You can also copy it directly using the "Copy to Clipboard" button.

## 📄 Generated Script Explained (Slightly More Technical)

The generated script includes commands for:

  * Creating a Bridge to combine network interfaces (wireless and ethernet).
  * Wireless interface settings including band, channel width, country, frequency, operating mode (AP/Station), SSID, and NV2 security.
  * Wireless security profiles (WPA2-PSK).
  * Adding `wlan1` and `ether1` interfaces to the bridge.
  * Disabling neighbor discovery for enhanced security.
  * Setting the IP address for the bridge.
  * Setting the system identity of the radio.
  * Changing the `admin` user's password.

## ⚙️ Requirements

  * Python 3.x
  * Python Libraries (will be installed automatically with pip):
      * `tkinter` (usually bundled with Python)
      * `ttkthemes`
      * `requests`

## 🚀 Installation

1.  **Install Python:** If you don't have Python, download and install it from [python.org](https://www.python.org/downloads/).
2.  **Download the Project:** Clone this repository to your computer or download the `mikrotik.py` file:
    ```bash
    git clone https://github.com/intellsoft/mikrotik-easy-wireless-link.git
    cd mikrotik-easy-wireless-link
    ```
3.  **Install Dependencies:** Open your terminal or Command Prompt, navigate to the project folder, and run:
    ```bash
    pip install ttkthemes requests
    ```
4.  **Run the Application:**
    ```bash
    python mikrotik.py
    ```

## 👨‍💻 About the Developer

This project was developed by [Mohammadali Abbaspour](https://intellsoft.ir/).

  * **Website:** [intellsoft.ir](https://intellsoft.ir/)
  * **GitHub:** [intellsoft](https://github.com/intellsoft)

## 📄 License

This project is released under the [MIT License](https://www.google.com/search?q=LICENSE).

## 📝 Version

**Version: 0.1**