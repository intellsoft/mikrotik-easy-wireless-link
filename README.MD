<div dir="rtl">

## ⚠️ توجه: این برنامه در حال توسعه و تکمیل شدن است

## ابزار تولید اسکریپت MikroTik

با این برنامه با حداقل دانش فنی میکروتیک لینک های رادیویی خود را تنظیم کنید!  
این ابزار رابط گرافیکی ساده‌ای برای تولید اسکریپت‌های MikroTik ارائه می‌دهد که به شما امکان می‌دهد تنظیمات اولیه دستگاه MikroTik خود را به سادگی پیکربندی کنید.

### ویژگی‌های اصلی
- تولید خودکار رمزهای عبور امن
- پشتیبانی از دو حالت رادیو:
  - اکسس پوینت (AP)
  - استیشن (Station)
- ذخیره خودکار اسکریپت در فایل `mikrotik_script.rsc`
- قابلیت کپی اسکریپت به کلیپ‌بورد
- رابط کاربری فارسی و راست‌چین
- راه‌اندازی سریع لینک‌های رادیویی با حداقل دانش فنی

### نحوه استفاده
1. حالت رادیو را انتخاب کنید (اکسس پوینت یا استیشن)
2. فیلدهای زیر را پر کنید:
   - رمز عبور جدید
   - نام رادیو (Identity)
   - آدرس IP
   - نام وایرلس (SSID)
   - رمز وایرلس
3. روی دکمه "تولید اسکریپت" کلیک کنید
4. اسکریپت تولید شده در پنجره نمایش داده می‌شود
5. برای کپی اسکریپت به کلیپ‌بورد از دکمه "کپی به کلیپ‌بورد" استفاده کنید

### نیازمندی‌ها
- Python 3.x
- کتابخانه‌های مورد نیاز:
  ```
  tkinter
  ```

### نحوه اجرا
```bash
python mikrotik.py
```

### تصاویر از محیط برنامه
(تصاویر بعداً اضافه خواهند شد)

### توسعه برنامه
این برنامه توسط محمدعلی عباسپور توسعه داده شده و در حال توسعه است. ویژگی‌های جدیدی به مرور اضافه خواهد شد. مشارکت در توسعه پروژه پذیرفته می‌شود.

[اینتل سافت](https://intellsoft.ir)

</div>

---

## MikroTik Script Generator Tool

## ⚠️ Note: This program is under development and not yet complete

With this tool, you can set up your MikroTik radio links with minimal technical knowledge!  
This application provides a simple graphical interface for generating MikroTik configuration scripts, allowing you to easily set up initial configurations for your MikroTik devices.

### Key Features
- Automatic generation of secure passwords
- Support for two radio modes:
  - Access Point (AP)
  - Station mode
- Auto-save scripts to `mikrotik_script.rsc` file
- Copy to clipboard functionality
- Persian RTL user interface
- Quick setup of radio links with minimal technical knowledge

### How to Use
1. Select radio mode (Access Point or Station)
2. Fill in the following fields:
   - New admin password
   - Device identity
   - IP address
   - WiFi SSID
   - WiFi password
3. Click "Generate Script" button
4. The generated script will appear in the output window
5. Use "Copy to Clipboard" button to copy the script

### Requirements
- Python 3.x
- Required libraries:
  ```
  tkinter
  ```

### How to Run
```bash
python mikrotik.py
```

### Application Screenshots
(Images will be added later)

### Development Status
This program was developed by [Your Name] and is currently under development. New features will be added incrementally. Contributions to the project are welcome.

[Intellsoft](https://intellsoft.ir)