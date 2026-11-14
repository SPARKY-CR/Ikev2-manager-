<div dir="rtl">

# Ikev2-manager

[![CI](https://github.com/SPARKY-CR/Ikev2-manager-/actions/workflows/ci.yml/badge.svg)](https://github.com/SPARKY-CR/Ikev2-manager-/actions/workflows/ci.yml) **نسخه‌ی 1.4.0**

**نصب و مدیریت سرور VPN مبتنی بر IKEv2/IPsec (با strongSwan) روی Ubuntu/Debian، با یک دستور.**
منوی متنی ساده، پروفایل آماده برای اندروید/آیفون/ویندوز/مک، تنظیمات کامل strongSwan و ربات تلگرام مخصوص ادمین.

🇬🇧 [English README](README.en.md)

> ✅ **وضعیت پروژه:** نسخه‌ی 1.4.0 — تست‌های CI سبز است و نصب روی سرور واقعی آزمایش شده است.
> اگر مشکلی دیدید لطفاً در بخش Issues گزارش دهید
> (متن خطا و خروجی `vpn version` را بنویسید، رمز و توکن را **هرگز** ننویسید).

---

## فهرست

- [امکانات](#امکانات)
- [پیش‌نیازها](#پیشنیازها)
- [نصب](#نصب)
- [بعد از نصب: باز کردن پورت‌ها](#بعد-از-نصب-باز-کردن-پورتها)
- [حالت IP یا دامنه؟](#حالت-ip-یا-دامنه)
- [منوی مدیریت](#منوی-مدیریت)
- [کاربران و پروفایل‌ها](#کاربران-و-پروفایلها)
- [نصب روی دستگاه‌ها](#نصب-روی-دستگاهها)
- [ربات تلگرام](#ربات-تلگرام)
- [تنظیمات پیشرفته strongSwan](#تنظیمات-پیشرفته-strongswan)
- [امنیت](#امنیت)
- [بکاپ و بازگردانی](#بکاپ-و-بازگردانی)
- [آپدیت](#آپدیت)
- [حذف](#حذف)
- [تمام دستورات](#تمام-دستورات)
- [عیب‌یابی](#عیبیابی)
- [آنچه نصب‌کننده روی سرور تغییر می‌دهد](#آنچه-نصبکننده-روی-سرور-تغییر-میدهد)
- [حریم خصوصی و اعتماد](#حریم-خصوصی-و-اعتماد)
- [ساختار ریپو و نگهداری](#ساختار-ریپو-و-نگهداری)
- [مشارکت، مجوز و سلب مسئولیت](#مشارکت-مجوز-و-سلب-مسئولیت)

---

## امکانات

| بخش | توضیح |
|---|---|
| نصب | یک دستور، ویزارد متنی (فقط شماره و Enter) یا نصب بدون سؤال با `--yes` |
| کاربران | افزودن، حذف، فعال/غیرفعال، تغییر رمز؛ رمز تصادفی قوی |
| پروفایل | اندروید (`.sswan` برای اپ strongSwan)، **ZedSecure** (لینک `zedsecure://`)، آیفون/آیپد/مک (`.mobileconfig`)، ویندوز (اسکریپت PowerShell) |
| حالت‌ها | **حالت IP** (بدون دامنه، با CA شخصی) یا **حالت دامنه** (Let's Encrypt با تمدید خودکار) |
| تنظیمات | DNS، رنج IP کاربران، مسیرهای split-tunnel، پروپوزال‌های IKE/ESP، DPD، MOBIKE، تایمرها، چند دستگاه برای هر کاربر، MSS، NAT، پورت‌های اضافه فایروال، سطح لاگ |
| دسترسی کامل | با «Raw snippets» هر گزینه‌ی strongSwan را اضافه کنید (اعتبارسنجی + برگشت خودکار) |
| امنیت | فایروال اختیاری (فقط SSH و VPN)، **جداسازی کلاینت‌ها و مسدود کردن دسترسی به metadata ابری و شبکه‌های خصوصی**، fail2ban، آپدیت امنیتی خودکار، ترمز اختیاری برای حدس رمز، محافظ اختیاری نشت IPv6 |
| ربات | کاربران، پروفایل‌ها، آنلاین‌ها، وضعیت، بکاپ **رمزنگاری‌شده**، DNS، اعلان‌ها؛ حذف خودکار اطلاعات ورود از چت؛ فارسی و انگلیسی؛ فقط برای ادمین |
| نگهداری | بکاپ **رمزنگاری‌شده**، بازگردانی با اعتبارسنجی آرشیو، آپدیت **راستی‌آزمایی‌شده (چک‌سام + امضا)** با برگشت خودکار، حذف کامل |

---

## پیش‌نیازها

- سرور **Ubuntu یا Debian** (با systemd) و IP عمومی؛ دسترسی `root` یا `sudo`.
  آزمایش اصلی روی Ubuntu بوده؛ Debian باید کار کند ولی کمتر آزمایش شده است.
- **VPS واقعی (KVM)** توصیه می‌شود. بعضی سرورهای OpenVZ/LXC اجازه‌ی IPsec نمی‌دهند.
- پورت‌های **UDP 500** و **UDP 4500** در فایروال سرویس‌دهنده باز باشد
  (در حالت دامنه، **TCP 80** هم موقع گرفتن/تمدید گواهی).
- دامنه **اختیاری** است.

---

## نصب

روی سرور (با کاربری که sudo دارد) این دستور را بزنید. **هیچ‌چیز را عوض نکنید**؛ همین‌طور که هست کپی کنید:

```bash
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/SPARKY-CR/Ikev2-manager-/main/install.sh)"
```

ویزارد متنی می‌پرسد:

1. حالت: بدون دامنه (IP) یا با دامنه (Let's Encrypt)
2. نام کاربر اول (رمز قوی خودکار ساخته می‌شود)
3. فایروال، fail2ban، آپدیت امنیتی خودکار
4. ربات تلگرام (اختیاری)

در پایان آدرس سرور، نام کاربری و رمز نمایش داده می‌شود. بعد از آن هر زمان `sudo vpn` منوی مدیریت را باز می‌کند.

**نصب بدون سؤال** (مثلاً برای اسکریپت‌ها):

```bash
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/SPARKY-CR/Ikev2-manager-/main/install.sh)" -- \
  --yes --user alice --firewall --fail2ban --autoupdate
```

گزینه‌های نصب‌کننده:

| گزینه | معنی |
|---|---|
| `--yes` | بدون سؤال؛ با گزینه‌های داده‌شده و پیش‌فرض‌ها |
| `--domain example.com` | حالت دامنه (Let's Encrypt) |
| `--email you@example.com` | ایمیل Let's Encrypt (اختیاری) |
| `--ip 1.2.3.4` | IP عمومی را دستی بدهید (جستجوی خودکار IP انجام نمی‌شود) |
| `--user NAME` / `--pass PASS` | کاربر اول و رمزش (پیش‌فرض: `user1` و رمز تصادفی) |
| `--firewall` / `--no-firewall` | فایروال |
| `--fail2ban` / `--no-fail2ban` | محافظت SSH |
| `--autoupdate` / `--no-autoupdate` | آپدیت امنیتی خودکار |
| `--bot-token TOKEN --admin-id ID` | فعال‌سازی ربات تلگرام |
| `--from DIR` | استفاده از فایل‌های یک clone محلی به‌جای دانلود |
| `--upgrade` | آپدیت نصب موجود |

> نکته: `--pass` روی خط فرمان در لیست پروسه‌ها دیده می‌شود. بهتر است رمز را ندهید تا تصادفی ساخته شود، یا از متغیر محیطی `IKEV2MGR_PASS` استفاده کنید.
> رمز باید **حداقل ۱۲ کاراکتر** باشد. توکن ربات را هم می‌توان با `IKEV2MGR_BOT_TOKEN` داد. همه‌ی ورودی‌ها قبل از نصب اعتبارسنجی می‌شوند.

**نصب از clone** (اگر نمی‌خواهید دستور `curl` را اجرا کنید یا می‌خواهید اول کد را بخوانید):

```bash
git clone https://github.com/SPARKY-CR/Ikev2-manager-.git
cd $(basename SPARKY-CR/Ikev2-manager-)
sudo bash install.sh --from .
```

**نسخه‌ی ثابت (پین):** به‌جای `main` می‌توانید یک commit بدهید (در حال حاضر tag منتشر نشده است). هم آدرس و هم متغیر را بگذارید:

```bash
sudo IKEV2MGR_BRANCH=32fc719 bash -c "$(curl -fsSL https://raw.githubusercontent.com/SPARKY-CR/Ikev2-manager-/32fc719/install.sh)"
```

**بررسی نصب‌کننده قبل از اجرا** (نصب‌کننده نمی‌تواند خودش را راستی‌آزمایی کند؛ ولی هر چیزی که بعد از آن دانلود می‌شود راستی‌آزمایی می‌شود):

```bash
curl -fsSLO https://raw.githubusercontent.com/SPARKY-CR/Ikev2-manager-/main/install.sh
sha256sum install.sh        # با خط install.sh در فایل SHA256SUMS ریپو مقایسه کنید
sudo bash install.sh
```

در این حالت `vpn update` هم از همان نسخه‌ی پین‌شده می‌خواند، یعنی آپدیتی نمی‌بینید تا خودتان منبع را عوض کنید (`vpn update --base ...`).

> نصب روی سروری که قبلاً strongSwan را دستی تنظیم کرده‌اید: تنظیمات قبلی در `/var/backups/ikev2/pre-install-...` نگه‌داری و بعد جایگزین می‌شود.

---

## بعد از نصب: باز کردن پورت‌ها

نصب‌کننده فقط **فایروال خود سرور** را مدیریت می‌کند. فایروال **سرویس‌دهنده** (مثلاً Security Group در AWS) جداست و باید دستی باز شود:

| پروتکل | پورت | کاربرد |
|---|---|---|
| UDP | 500 | IKE |
| UDP | 4500 | IKE/ESP روی NAT |
| TCP | 80 | فقط حالت دامنه، برای Let's Encrypt |
| TCP | پورت SSH (پیش‌فرض 22) | مدیریت سرور |

در AWS: EC2 ← Security Groups ← Inbound rules ← Add rule ← نوع Custom UDP برای هر دو پورت.
بعضی سرویس‌دهنده‌ها (مثل Oracle Cloud) علاوه بر Security List، iptables خودشان را هم دارند.

---

## حالت IP یا دامنه؟

| | حالت IP | حالت دامنه |
|---|---|---|
| نیاز به دامنه | خیر | بله (رکورد A به IP سرور) |
| گواهی سرور | CA شخصی (self-signed) | Let's Encrypt (عمومی، تمدید خودکار) |
| نصب CA روی دستگاه | **لازم** (داخل پروفایل‌ها گنجانده می‌شود) | لازم نیست |
| ساده‌ترین برای | استفاده‌ی شخصی سریع | اپ‌هایی که از IKEv2 داخلی اندروید استفاده می‌کنند، چند کاربر |
| تغییر IP سرور | `vpn ip refresh` + ارسال پروفایل‌های جدید | فقط رکورد DNS را عوض کنید |

جابه‌جایی بعد از نصب: `sudo vpn domain set example.com` یا `sudo vpn domain unset`. بعد از جابه‌جایی آدرس سرور عوض می‌شود و باید پروفایل جدید به کاربران بدهید.

---

## منوی مدیریت

دستور `sudo vpn` یک منوی متنی شماره‌دار باز می‌کند (عدد + Enter):

```
 1) Users & client profiles
 2) Status & connected clients
 3) Server, certificates, domain
 4) Advanced strongSwan settings
 5) Telegram bot
 6) Security (firewall, fail2ban, auto-updates)
 7) Backup & restore
 8) Updates
 9) Uninstall
 0) Exit
```

(متن منو عمداً انگلیسی است تا روی هر ترمینال درست نمایش داده شود.)

---

## کاربران و پروفایل‌ها

```bash
sudo vpn user add alice          # رمز تصادفی
sudo vpn user add bob 'Pass.12345'
sudo vpn user list
sudo vpn user disable bob        # قطع و غیرفعال
sudo vpn user enable bob
sudo vpn user passwd alice       # رمز جدید تصادفی
sudo vpn user del bob
sudo vpn profile alice           # ساخت فایل‌های پروفایل در /root/ikev2-profiles/alice
sudo vpn zed alice               # لینک ZedSecure
```

- نام کاربری: حروف انگلیسی، عدد و `_ . -` تا ۳۲ کاراکتر، و باید با حرف/عدد شروع شود.
- رمز: ۸ تا ۶۴ کاراکتر از حروف انگلیسی، عدد و `. _ @ + = , ! % ^ * ~ -`.
- هر کاربر می‌تواند چند دستگاه داشته باشد (`UNIQUE=no`، پیش‌فرض).

فایل‌هایی که `vpn profile` می‌سازد:

| فایل | برای |
|---|---|
| `NAME.sswan` | اندروید، اپ strongSwan |
| `zedsecure-NAME.txt` | لینک‌های import برای ZedSecure |
| `NAME.mobileconfig` | آیفون، آیپد، مک |
| `NAME-windows.ps1` | ویندوز |
| `ca.crt` | گواهی CA (فقط حالت IP) |
| `README-NAME.txt` | راهنمای کوتاه + اطلاعات اتصال |

> این فایل‌ها حاوی اطلاعات ورود هستند؛ مثل رمز با آن‌ها رفتار کنید. دسترسی فایل‌ها `600` است.

---

## نصب روی دستگاه‌ها

مشخصات اتصال: **IKEv2 با EAP-MSCHAPv2** (نام کاربری و رمز)؛ آدرس سرور = IP یا دامنه.

### اندروید (اپ strongSwan)
1. اپ **strongSwan VPN Client** را از Google Play نصب کنید.
2. منو ← **Import VPN profile** ← فایل `NAME.sswan`.
3. رمز را وارد کنید (داخل فایل ذخیره نمی‌شود) و Import را بزنید، بعد روی پروفایل بزنید تا وصل شود.
4. در حالت IP، گواهی CA داخل پروفایل گنجانده شده است.

### اندروید (ZedSecure)
1. لینک `zedsecure://...` را از ربات یا فایل `zedsecure-NAME.txt` یا دستور `vpn zed NAME` کپی کنید.
2. در [ZedSecure](https://github.com/CluvexStudio/ZedSecure) از کلیپ‌بورد import کنید.
3. اگر اپ رمز داخل لینک را نپذیرفت، لینک دوم (بدون رمز) را import کنید و رمز را دستی وارد کنید.

> فرمت لینک با بررسی خروجی خود اپ تهیه شده و ممکن است با نسخه‌های بعدی اپ تغییر کند.
> ZedSecure از IKEv2 داخلی اندروید استفاده می‌کند؛ با **حالت دامنه** معمولاً کم‌دردسرتر است.

### آیفون / آیپد / مک
1. فایل `NAME.mobileconfig` را باز کنید (از Telegram یا Files). Settings ← **Profile Downloaded** ← Install.
2. **حالت IP:** Settings ← General ← About ← **Certificate Trust Settings** ← اعتماد کامل به CA را روشن کنید.
3. Settings ← VPN ← روشن کنید.

### ویندوز
1. PowerShell را با **Run as Administrator** باز کنید.
2. اسکریپت `NAME-windows.ps1` را اجرا کنید (اگر لازم شد: `Set-ExecutionPolicy -Scope Process Bypass`).
3. Settings ← Network & Internet ← VPN ← اتصال را بزنید و رمز را وارد کنید.

### دستی (هر کلاینت IKEv2 دیگر)
نوع **IKEv2/EAP-MSCHAPv2**، آدرس سرور، نام کاربری، رمز؛ در حالت IP فایل `ca.crt` را به‌عنوان CA معتبر اضافه کنید.

---

## ربات تلگرام

ربات **فقط به یک آیدی عددی (ادمین)** پاسخ می‌دهد و **فقط در چت خصوصی**؛ بقیه نادیده گرفته می‌شوند.

**راه‌اندازی:**
1. در تلگرام به **@BotFather** پیام بدهید، `/newbot` را بزنید و **توکن** را بگیرید.
2. به **@userinfobot** پیام بدهید و **آیدی عددی خودتان** را بگیرید.
3. ربات جدید را باز کنید و **Start** بزنید.
4. در ویزارد نصب (یا `sudo vpn` ← Telegram bot ← Set bot token) توکن و آیدی را وارد کنید.
5. در تلگرام `/start` را بفرستید.

**امکانات:**
- ساخت کاربر و دریافت **اطلاعات اتصال + همه‌ی فایل‌های پروفایل + لینک ZedSecure** در چت
- فعال/غیرفعال‌سازی، تغییر رمز، حذف کاربر (با تأیید)
- وضعیت سرور، لیست آنلاین‌ها (زمان اتصال و حجم نشست فعلی)، اطلاعات سرور، ری‌استارت VPN
- بکاپ (ساخت؛ ارسال فقط به‌صورت **رمزنگاری‌شده**، بخش «بکاپ و بازگردانی» را ببینید)
- تغییر **DNS** با چند ارائه‌دهنده‌ی آماده
- آپدیت strongSwan (apt) و آپدیت ابزار (از GitHub)
- **اعلان‌ها:** از کار افتادن/برگشت سرویس، منقضی‌شدن یا نزدیک شدن انقضای گواهی، اتصال/قطع کاربران (اختیاری)، نسخه‌ی جدید ابزار
- زبان **فارسی و انگلیسی** (دکمه‌ی تغییر زبان)

> ⚠️ پیام‌های تلگرام end-to-end رمزنگاری نیستند. ربات **رمز کاربران** را داخل چت شما می‌فرستد. برای کم کردن خطر:
> پیام‌ها و فایل‌های حاوی اطلاعات ورود **بعد از ۳۰ دقیقه از چت پاک می‌شوند** (در بخش «اعلان‌ها» قابل خاموش‌کردن است)،
> رمزی که خودتان در چت می‌نویسید بلافاصله بعد از خوانده‌شدن پاک می‌شود، و رمزها هرگز به‌صورت آرگومان به دستورها داده نمی‌شوند.
> **بکاپ** (کلیدهای خصوصی + رمز همه) فقط **رمزنگاری‌شده** و برای کلیدی فرستاده می‌شود که نیمه‌ی خصوصی‌اش پیش خودتان است
> (`sudo vpn backup key init`)؛ بدون کلید، ربات از ارسال بکاپ خودداری می‌کند.
> فقط روی حساب و دستگاهی که به آن اعتماد دارید استفاده کنید، و توکن ربات را به کسی ندهید
> (در `/etc/ikev2/config.env` با دسترسی `600` نگهداری می‌شود). سرویس ربات با گزینه‌های sandbox سیستم‌د (`NoNewPrivileges`، `PrivateTmp` و ...) اجرا می‌شود.

---

## تنظیمات پیشرفته strongSwan

از منو: **4) Advanced strongSwan settings**، یا خط فرمان:

```bash
sudo vpn get             # فهرست همه‌ی تنظیمات و مقدار فعلی
sudo vpn get DNS         # جزئیات یک تنظیم
sudo vpn set DNS 9.9.9.9,149.112.112.112
sudo vpn set DNS default # برگشت به پیش‌فرض
sudo vpn reset --yes     # برگشت همه‌ی تنظیمات به پیش‌فرض (بدون --yes تأیید می‌خواهد)
```

هر تغییر: **اعتبارسنجی می‌شود** ← پیکربندی دوباره ساخته و بارگذاری می‌شود ← اگر سرور رد کند **مقدار قبلی خودکار برمی‌گردد**.
بعد از تغییر DNS / رنج IP / مسیرها، کاربران باید دوباره وصل شوند.

| تنظیم | معنی | پیش‌فرض |
|---|---|---|
| `DNS` | سرورهای DNS که به کلاینت داده می‌شود | `1.1.1.1,8.8.8.8` |
| `POOL` | رنج IP مجازی کاربران (CIDR از /8 تا /30) | `10.30.0.0/16` |
| `LOCAL_TS` | مسیرهای ارسالی به کلاینت. `0.0.0.0/0` یعنی همه‌ی ترافیک؛ غیر از آن یعنی split tunnel | `0.0.0.0/0` |
| `IKE_PROPOSALS` | پروپوزال‌های IKE (فاز ۱) که سرور می‌پذیرد | `default,aes256-sha256-modp2048,...` |
| `ESP_PROPOSALS` | پروپوزال‌های ESP (فاز ۲) | `default,aes256-sha256-modp2048,...` |
| `DPD_DELAY` | فاصله‌ی تشخیص قطع‌شدن کلاینت | `30s` |
| `FRAGMENTATION` | تکه‌تکه کردن IKE (`yes/no/force/accept`) | `yes` |
| `MOBIKE` | حفظ اتصال هنگام تغییر شبکه (وای‌فای ↔ دیتا) | `yes` |
| `UNIQUE` | اگر یک کاربر دوباره وصل شد: `no` (چند نشست)، `never`، `keep`، `replace` | `no` |
| `REKEY_TIME` | زمان rekey کلید IKE | پیش‌فرض strongSwan |
| `REAUTH_TIME` | احراز هویت دوباره‌ی اجباری بعد از این مدت | غیرفعال |
| `CHILD_REKEY_TIME` | زمان rekey کلید ESP | پیش‌فرض strongSwan |
| `CHILD_LIFE_TIME` | طول عمر کلید ESP | پیش‌فرض strongSwan |
| `SEND_CERT` | زمان ارسال گواهی توسط سرور (`always/ifasked/never`) | `always` |
| `MSS_CLAMP` | کاهش MSS برای رفع کندی/گیر کردن صفحه‌ها (`pmtu`، `off` یا عدد ۵۳۶ تا ۱۴۶۰) | `pmtu` |
| `NAT` | NAT (masquerade) خروجی ترافیک VPN | `yes` |
| `FW_EXTRA_TCP` / `FW_EXTRA_UDP` | پورت‌های اضافه برای باز بودن وقتی فایروال روشن است | خالی |
| `LOG_LEVEL` | جزئیات لاگ strongSwan (`default` یا `-1` تا `4`) | `default` |
| `CLIENT_ISOLATION` | کلاینت‌ها نمی‌توانند به هم دسترسی داشته باشند (دستگاه به دستگاه) | `yes` |
| `BLOCK_PRIVATE` | کلاینت‌ها نمی‌توانند به شبکه‌های خصوصی پشت سرور (10/8، 172.16/12، 192.168/16، 100.64/10) برسند؛ DNSهای پوش‌شده و مسیرهای `LOCAL_TS` همچنان در دسترس‌اند | `yes` |
| `IKE_RATE_LIMIT` | `off` یا یک عدد: حداکثر هندشیک‌های جدید IKE در دقیقه از هر IP روی UDP/500 (ترمز حدس رمز؛ مثلاً `60`) | `off` |
| `IPV6_BLOCK` | `yes` یعنی `::/0` هم داخل تونل برود و دور ریخته شود تا IPv6 دور از VPN نشت نکند (**آزمایشی**؛ نیاز به `0.0.0.0/0` در `LOCAL_TS`) | `no` |

**نمونه‌ها:**

```bash
sudo vpn preset dns adguard                       # DNS با حذف تبلیغات
sudo vpn preset dns list                          # همه‌ی پریست‌ها
sudo vpn set LOCAL_TS 10.0.0.0/8,192.168.1.0/24   # فقط این شبکه‌ها از VPN بروند (split tunnel)
sudo vpn set UNIQUE replace                       # هر کاربر فقط یک دستگاه (نشست جدید جایگزین قبلی)
sudo vpn set MSS_CLAMP 1360                       # اگر بعضی سایت‌ها باز نمی‌شوند
sudo vpn preset ike strict-sha2                   # لیست صریح فقط-SHA-2؛ بدون SHA-1 و بدون لیست پیش‌فرض strongSwan (کلاینت‌های قدیمی ممکن است وصل نشوند)
sudo vpn set IKE_RATE_LIMIT 60                    # ترمز حدس رمز: حداکثر ۶۰ هندشیک جدید در دقیقه از هر IP
```

پریست‌های DNS: `cloudflare`، `google`، `quad9`، `adguard`، `cloudflare-family`، `opendns`.

### دسترسی کامل: Raw snippets

هر گزینه‌ای از strongSwan که در جدول بالا نیست را می‌توانید مستقیم اضافه کنید:

```bash
sudo vpn raw list
sudo vpn raw edit child        # ویرایش با nano
sudo vpn raw show child
sudo vpn raw clear child
printf 'keyingtries = 3\n' | sudo vpn raw set connection   # از ورودی استاندارد
```

| بخش | کجا اضافه می‌شود |
|---|---|
| `connection` | داخل `connections { rw { ... } }` |
| `local` | بلوک `local { ... }` سرور |
| `remote` | بلوک `remote { ... }` کلاینت |
| `child` | داخل `children { net { ... } }` (مثلاً `inactivity = 2h`) |
| `pools` | داخل `pools { rw_pool { ... } }` |
| `extra` | کل بخش‌های اضافه در انتهای `swanctl.conf` (کانکشن/CA/secret بیشتر) |
| `charon` | فایل `strongswan.conf` (مثلاً `charon { ikesa_table_size = 64 }`) |

بعد از هر ویرایش، پیکربندی بارگذاری می‌شود؛ اگر strongSwan رد کند، محتوای قبلی خودکار برمی‌گردد.
مرجع گزینه‌ها: <https://docs.strongswan.org/docs/latest/swanctl/swanctlConf.html>

نمایش پیکربندی نهایی (رمزها پنهان): `sudo vpn conf show`.

> پورت‌های IKE (500 و 4500) عمداً قابل تغییر نیستند، چون کلاینت‌های داخلی گوشی فقط همین‌ها را قبول می‌کنند.

---

## امنیت

```bash
sudo vpn fw on            # فقط SSH + VPN ورودی؛ بقیه DROP
sudo vpn fw ports "22 2222"
sudo vpn fw off
sudo vpn security fail2ban
sudo vpn security autoupdate
```

- **فایروال:** یک chain به نام `IKEV2_FW` می‌سازد. نشست SSH فعلی قطع نمی‌شود، ولی اگر پورت SSH را اشتباه بدهید ممکن است نتوانید **نشست جدید** بسازید. پورت‌های SSH از `sshd` و نشست فعلی تشخیص داده می‌شوند؛ پورت 22 همیشه اضافه است. پورت‌های دیگر را با `FW_EXTRA_TCP/UDP` اضافه کنید.
- **کلاینت‌ها به چه چیزهایی می‌رسند** (chain به نام `IKEV2_FWD`؛ `vpn fw status`): هرگز به فضای link-local (این **سرویس metadata ابری** `169.254.169.254` را می‌بندد)، به‌طور پیش‌فرض نه به هم (`CLIENT_ISOLATION`) و نه به شبکه‌های خصوصی پشت سرور (`BLOCK_PRIVATE`). بقیه‌ی ترافیک فوروارد و NAT می‌شود.
- **IPv6 داخل تونل نمی‌رود.** اگر شبکه‌ی کلاینت IPv6 هم دارد، بعضی ترافیک‌ها می‌توانند خارج از VPN بروند. پروفایل اندروید IPv6 را می‌بندد؛ در بقیه‌ی دستگاه‌ها IPv6 شبکه را خاموش کنید یا `IPV6_BLOCK=yes` را (آزمایشی) امتحان کنید.
- **رمزها:** حداقل ۱۲ کاراکتر (رمز خودکار: ۱۶ کاراکتر تصادفی)، رمزهای ضعیف/رایج پذیرفته نمی‌شوند، و اگر اعمال تنظیمات شکست بخورد هیچ کاربری نیمه‌ساخته یا نیمه‌حذف نمی‌ماند. برای رمز اشتباه **قفل (lockout)** وجود ندارد: رمز قوی بگذارید و اگر در `vpn logs` حدس رمز دیدید `IKE_RATE_LIMIT` را تنظیم کنید. (fail2ban فقط از SSH محافظت می‌کند.)
- **fail2ban:** برای SSH (۵ تلاش ناموفق در ۱۰ دقیقه ← ۱ ساعت بن).
- **آپدیت امنیتی خودکار:** با `unattended-upgrades` (به‌روزرسانی‌های امنیتی strongSwan هم شامل می‌شود).
- رمز کاربران چون EAP-MSCHAPv2 لازم دارد در `/etc/ikev2/users.db` به‌صورت **متن ساده** (فقط root، دسترسی `600`) نگه‌داری می‌شود. دستورهایی که وضعیت را تغییر می‌دهند با قفل سریالی و با نوشتن اتمیک اجرا می‌شوند؛ `config.env` فقط **پارس** می‌شود و هرگز اجرا نمی‌شود.
- **CA در حالت IP:** کلید CA (`/etc/ikev2/pki/ca.key`، دسترسی `600`) با `pathlen:0` ساخته می‌شود (فقط می‌تواند گواهی کاربرنهایی صادر کند) ولی مثل هر CA شخصی **name constraints ندارد**. هر کس این کلید را بدزدد می‌تواند برای دستگاه‌هایی که به این CA اعتماد دارند جعل هویت سایت‌ها کند. با آن مثل رمز root رفتار کنید، هرگز بدون رمزنگاری از سرور بیرون نبریدش (بخش بکاپ) و برای بیش از چند دستگاه شخصی **حالت دامنه** را ترجیح دهید (CA عمومی؛ چیزی روی دستگاه‌ها نصب نمی‌شود).

---

## بکاپ و بازگردانی

```bash
sudo vpn backup           # ساخت بکاپ در /var/backups/ikev2 (پوشه 700؛ ۱۰ بکاپ آخر نگه‌داری می‌شود)
sudo vpn backup --encrypt # بکاپ + یک نسخه‌ی رمزنگاری‌شده (*.tar.gz.enc)
sudo vpn backups          # فهرست
sudo vpn restore /var/backups/ikev2/ikev2-backup-YYYYMMDD-HHMMSS.tar.gz
sudo vpn restore FILE.tar.gz.enc --key backup.key
```

بکاپ شامل **کلیدهای خصوصی و رمز همه‌ی کاربران** است (فایل‌ها `0600` هستند). قبل از هر آپدیت، بازگردانی و حذف هم خودکار بکاپ گرفته می‌شود.

**فقط نسخه‌ی رمزنگاری‌شده باید از سرور بیرون برود.** راه‌اندازی:

```bash
sudo vpn backup key init                 # جفت‌کلید می‌سازد؛ کلید خصوصی را فقط یک بار چاپ می‌کند (در password manager ذخیره کنید؛ روی سرور نگه‌داری نمی‌شود)
sudo vpn backup key set backup.crt       # یا گواهی خودتان را بدهید (کلید خصوصی از همان اول فقط پیش شماست)
sudo vpn backup key show | remove
# باز کردن روی هر کامپیوتر:
openssl cms -decrypt -binary -inform DER -in FILE.enc -inkey backup.key -out backup.tar.gz
```

برای ساخت گواهی روی کامپیوتر خودتان: `openssl req -x509 -newkey rsa:4096 -nodes -keyout backup.key -out backup.crt -days 36500 -subj /CN=ikev2-backup`
(فقط RSA با حداقل ۲۰۴۸ بیت پذیرفته می‌شود). ربات تلگرام فقط همین نسخه‌ی رمزنگاری‌شده را می‌فرستد و بدون کلید از ارسال بکاپ خودداری می‌کند.

**بازگردانی امن:** قبل از استخراج، آرشیو **اعتبارسنجی** می‌شود (فقط پوشه‌های خود ابزار، بدون مسیر مطلق یا `..`، بدون لینکی که از آن پوشه‌ها بیرون برود، بدون فایل setuid یا device). سپس یک **کپی ایمنی از وضعیت فعلی** گرفته می‌شود، بازگردانی انجام می‌شود و پیکربندی دوباره اعمال می‌شود.

---

## آپدیت

```bash
sudo vpn update --check   # فقط بررسی
sudo vpn update           # آپدیت از GitHub (با تأیید)
sudo vpn update --base https://...   # تغییر منبع آپدیت (فقط https)
sudo vpn upgrade-strongswan   # خود strongSwan از طریق apt
```

آپدیت ابزار: فایل‌ها در یک پوشه‌ی خصوصی دانلود می‌شوند ← **راستی‌آزمایی (چک‌سام `SHA256SUMS` و، وقتی کلید انتشار پین شده، امضا) پیش از اجرای هر چیزی** ← بکاپ ← نصب ← **خودآزمایی** ← اگر خودآزمایی رد شود، **نسخه‌ی قبلی خودکار برمی‌گردد**. کاربران، گواهی‌ها و تنظیمات حفظ می‌شوند.
منبع آپدیت فقط `https://` پذیرفته می‌شود (`http://` رد می‌شود). نسخه‌ی قدیمی‌تر بدون `--force` نصب نمی‌شود.
ربات روزی یک‌بار نسخه‌ی جدید را بررسی و **فقط اطلاع می‌دهد**؛ بدون تأیید شما چیزی نصب نمی‌شود.

آپدیت از clone محلی (کدی که خودتان انتخاب کرده‌اید؛ امضا بررسی نمی‌شود): `sudo vpn update /path/to/clone`.

---

## حذف

```bash
sudo vpn uninstall           # حذف ابزار، ربات، قوانین فایروال/NAT و پیکربندی VPN (بکاپ نهایی ساخته می‌شود؛ باید YES تایپ کنید)
sudo vpn uninstall --purge   # علاوه بر آن پکیج‌های strongSwan، همه‌ی داده‌ها در /etc/ikev2 و پروفایل‌های خروجی‌گرفته‌شده (حاوی رمز) را هم حذف می‌کند
```

بکاپ‌ها در `/var/backups/ikev2` باقی می‌مانند. بدون `--purge` پروفایل‌های `/root/ikev2-profiles` (حاوی رمز) حذف نمی‌شوند؛ اگر لازم ندارید دستی پاک کنید.

---

## تمام دستورات

```
sudo vpn                                        منوی متنی
vpn help | version | status | online | logs [N]
vpn user list | add NAME [PASS|--stdin] | del | enable | disable | passwd NAME [PASS|auto|--stdin] | show
vpn profile NAME [DIR]    vpn zed NAME [--nopw]    vpn ca
vpn get [KEY]    vpn set KEY VALUE    vpn reset [--yes]
vpn preset dns NAME|list    vpn preset ike compat|strict-sha2
vpn raw list | show | edit | set | clear NAME
vpn conf show | apply
vpn restart    vpn cert info | renew [--force]
vpn domain set DOMAIN [EMAIL] | unset    vpn ip refresh
vpn fw on | off | status | ports "22 2222"
vpn security fail2ban | autoupdate
vpn bot setup TOKEN|- ADMIN_ID | on | off | status | test | logs     ("-" توکن را از stdin می‌خواند)
vpn backup [--encrypt] | backups | restore FILE [--key PRIVATE_KEY]
vpn backup key init | set CERT.pem | show | remove     vpn backup decrypt FILE.enc KEY [OUT]
vpn update [--check] [--yes] [--force] [--base https://...] | upgrade-strongswan
vpn uninstall [--purge] [--yes]
```

**همه‌ی دستورهای `vpn` را با `sudo` اجرا کنید** (فایل تنظیمات فقط برای root قابل‌خواندن است).

---

## عیب‌یابی

**وصل نمی‌شود:**
1. پورت‌های **UDP 500/4500** در فایروال سرویس‌دهنده (مثلاً Security Group) باز باشد. شایع‌ترین علت است.
2. `sudo vpn status` ← سرویس باید `running` باشد. لاگ: `sudo vpn logs 100` یا `sudo journalctl -u strongswan -f` هنگام تلاش برای اتصال.
3. رمز و نام کاربری را چک کنید و `vpn user list` که کاربر `enabled` باشد.
4. **آیفون در حالت IP:** اعتماد کامل به CA را در Certificate Trust Settings روشن کرده باشید.
5. اگر IP سرور عوض شده (در حالت IP): `sudo vpn ip refresh` و پروفایل جدید بدهید.
6. ساعت سرور و دستگاه درست باشد (گواهی‌ها به زمان حساس‌اند).

**وصل می‌شود ولی اینترنت ندارد:** `sudo vpn get NAT` باید `yes` باشد؛ DNS را عوض کنید (`vpn preset dns cloudflare`)؛ `ip_forward` را چک کنید (`sysctl net.ipv4.ip_forward` باید `1` باشد).

**بعضی سایت‌ها کند یا باز نمی‌شوند:** `sudo vpn set MSS_CLAMP 1360`.

**فایروال و قفل شدن از SSH:** اگر با `vpn fw on` نشست جدید SSH نمی‌گیرید، از کنسول وب سرویس‌دهنده وارد شوید و `sudo vpn fw off` را بزنید.

**ویندوز وصل نمی‌شود:** اسکریپت PowerShell را با Administrator اجرا کنید؛ اسکریپت تنظیمات رمزنگاری را هم هماهنگ با سرور می‌گذارد.

**ربات جواب نمی‌دهد:** `sudo vpn bot status` و `sudo vpn bot logs`؛ توکن و آیدی درست باشد و در چت با ربات یک بار Start زده باشید.

---

## آنچه نصب‌کننده روی سرور تغییر می‌دهد

شفاف و قابل بررسی:

| مورد | مسیر / توضیح |
|---|---|
| پکیج‌ها (apt) | `strongswan`، `strongswan-swanctl`، `strongswan-pki`، `charon-systemd`، `libcharon-extra-plugins`، `libcharon-extauth-plugins`، `iptables`، `curl`، `openssl`، `python3`؛ در حالت دامنه `certbot`؛ اختیاری: `fail2ban`، `unattended-upgrades` |
| فایل‌های ابزار | `/usr/local/bin/vpn`، `/opt/ikev2/` |
| تنظیمات و داده | `/etc/ikev2/` (تنظیمات، کاربران، CA، snippetها)، `/var/lib/ikev2/`، `/var/backups/ikev2/` |
| strongSwan | `/etc/swanctl/` (تنظیمات، گواهی‌ها، کلید)، `/etc/strongswan.d/ikev2-manager.conf` |
| سرویس‌های systemd | `ikev2-net` (قوانین شبکه)، `ikev2-bot` (ربات)، `ikev2-certcheck.timer` (بررسی روزانه‌ی گواهی) |
| شبکه | `/etc/sysctl.d/99-ikev2.conf` (IP forwarding)؛ قوانین iptables با برچسب `ikev2-mgr` (NAT، FORWARD، MSS) و chain به نام `IKEV2_FW` در صورت فعال بودن فایروال |
| اختیاری | `/etc/fail2ban/jail.d/ikev2.local`، `/etc/apt/apt.conf.d/20auto-upgrades` |
| پروفایل‌های خروجی | `/root/ikev2-profiles/` (با دستور `vpn profile`) |

اگر قبلاً `/etc/swanctl/swanctl.conf` دستی داشتید، قبل از جایگزینی در `/var/backups/ikev2/pre-install-*` کپی می‌شود.

---

## حریم خصوصی و اعتماد

**این پروژه هیچ تلمتری یا ارسال آماری ندارد.** سرویس‌های بیرونی که ممکن است با آن‌ها تماس بگیرد:

| سرویس | چه زمانی |
|---|---|
| GitHub (`raw.githubusercontent.com`) | نصب و آپدیت ابزار، و بررسی نسخه‌ی جدید |
| `ifconfig.me`، `api.ipify.org`، `ipv4.icanhazip.com` | فقط برای تشخیص IP عمومی؛ با `--ip` اصلاً استفاده نمی‌شود |
| Let's Encrypt | فقط حالت دامنه |
| API تلگرام | فقط اگر ربات را فعال کرده باشید |
| مخازن apt | نصب و آپدیت پکیج‌ها |
| DNS انتخابی شما | به کلاینت‌ها داده می‌شود (پیش‌فرض: Cloudflare 1.1.1.1 و Google 8.8.8.8) |

**اعتماد به کد:** کد با دسترسی root اجرا می‌شود، پس به نگه‌دارنده‌ی پروژه اعتماد می‌کنید. انتشارها چندلایه محافظت می‌شوند:
`SHA256SUMS` فایل‌های خراب یا دستکاری‌شده را می‌گیرد؛ وقتی نگه‌دارنده **کلید امضا** منتشر کرده باشد (`release.pub` + `SHA256SUMS.sig`؛ بخش «برای نگه‌دارنده»)،
اولین نصب آن کلید را در `/etc/ikev2/release.pub` **پین می‌کند** و از آن به بعد **هر آپدیت باید با همان کلید امضا شده باشد**؛ یعنی توکن دزدیده‌شده‌ی GitHub یا یک mirror هک‌شده نمی‌تواند روی سرورهای موجود کد بفرستد
(کلید در اولین استفاده پین می‌شود: اگر اول یک نسخه‌ی بدون امضا نصب کنید، تا رسیدن نسخه‌ی امضاشده فقط چک‌سام اعمال می‌شود).
دانلود آپدیت **پیش از اجرا** راستی‌آزمایی می‌شود، هرگز روی `http://` نیست، و هرگز بدون تأیید شما نیست.
اگر این هم برایتان کافی نیست: اول کد را بخوانید (`git clone` و `--from .`) و به یک **tag/commit ثابت** پین کنید.

---

## ساختار ریپو و نگهداری

```
install.sh      نصب‌کننده (ویزارد + دانلود + راستی‌آزمایی + آپدیت با برگشت)
vpn             ابزار اصلی (منو و همه‌ی دستورها؛ یک فایل bash)
bot.py          ربات تلگرام (فقط کتابخانه‌ی استاندارد پایتون)
ikev2lib.py     توابع مشترک (پارس نشست‌ها، لینک ZedSecure، اعتبارسنجی آرشیو بکاپ)
VERSION         شماره‌ی نسخه
SHA256SUMS      چک‌سام فایل‌ها (install.sh، vpn، bot.py، ikev2lib.py، VERSION، release.pub)
SHA256SUMS.sig  امضای SHA256SUMS (بعد از bash tools/release.sh sign)
release.pub     کلید عمومی امضا (بعد از bash tools/release.sh init)
tools/release.sh  ابزار نگه‌دارنده: init | sign | verify
tests/          تست‌ها (bash tests/run_all.sh)
```

**تست‌ها:** `bash tests/run_all.sh`. نیازی به root، اینترنت یا strongSwan ندارد (`iptables`، `swanctl`، `pki`، `curl` و ... شبیه‌سازی می‌شوند؛ فایل‌های systemd با `systemd-analyze verify` بررسی می‌شوند).
پوشش: کاربران/قفل، تنظیمات، گواهی‌ها، پروفایل‌ها، قوانین فایروال، بکاپ، امنیت بازگردانی، مسیر آپدیت راستی‌آزمایی‌شده، نصب‌کننده و ربات.
آنچه تست‌ها **نمی‌توانند** پوشش بدهند: هسته‌ی واقعی/strongSwan/تلگرام و دستگاه‌های کلاینت واقعی. **قبل از انتشار هر نسخه، آن را روی یک VPS آزمایشی و با گوشی‌های خودتان امتحان کنید.**

**برای نگه‌دارنده (هر انتشار):**

```bash
bash tools/release.sh init      # فقط بار اول: کلید امضا (~/.ikev2mgr/release.key) می‌سازد و release.pub را در ریپو می‌نویسد
# تغییر کد، بالا بردن VERSION، و اجرای: bash tests/run_all.sh
bash tools/release.sh sign      # SHA256SUMS (install.sh، vpn، bot.py، ikev2lib.py، VERSION، release.pub) و SHA256SUMS.sig را می‌سازد
git add -A && git commit && git tag vX.Y.Z && git push --follow-tags     # همه چیز در یک commit
```

کلید خصوصی را آفلاین نگه دارید و **حتماً از آن بکاپ بگیرید**: سرورهایی که کلید عمومی‌اش را پین کرده‌اند فقط نسخه‌های امضاشده با آن را می‌پذیرند
(کلید جدید را می‌توان با یک نسخه‌ی امضاشده با کلید قدیمی معرفی کرد). اگر `release.pub` و `SHA256SUMS.sig` منتشر نکنید، فقط چک‌سام اعمال می‌شود.

**Fork:** `IKEV2MGR_REPO=user/repo` (و در صورت نیاز `IKEV2MGR_BRANCH`) را موقع نصب بدهید تا از ریپوی شما دانلود شود، و با کلید خودتان امضا کنید.

---

## مشارکت، مجوز و سلب مسئولیت

- **مشارکت:** Issue و Pull Request خوش‌آمد است. تغییرها را روی یک سرور آزمایشی تست کنید.
- **مشکل امنیتی:** [SECURITY.md](SECURITY.md) را ببینید (در Issue عمومی ننویسید).
- **مجوز:** MIT، فایل [LICENSE](LICENSE). strongSwan جداگانه و با مجوز خودش از مخزن توزیع نصب می‌شود و بخشی از این ریپو نیست.
- **سلب مسئولیت:** این نرم‌افزار «همان‌طور که هست» و بدون هیچ ضمانتی ارائه می‌شود. استفاده‌ی قانونی و رعایت قوانین کشور و سرویس‌دهنده‌ی سرور بر عهده‌ی خود شماست.

</div>
