# 🛡️ Backdoor Scanner

Backdoor Scanner adalah tool ringan untuk mendeteksi potensi **malicious file, backdoor, webshell, atau aktivitas mencurigakan** pada server Linux.
Tool ini melakukan pemindaian pada file, direktori, pola berbahaya, serta resource yang sering disalahgunakan oleh attacker.

Anda dapat menjalankan tool ini secara manual atau dijadwalkan melalui **cronjob** untuk monitoring berkala.

---

## 📸 Screenshot

<img src="https://raw.githubusercontent.com/security007/backdoor_scanner/master/scan.png" width="600">

<img src="https://raw.githubusercontent.com/security007/backdoor_scanner/master/results.png" width="600">

---

## 📥 Download

Clone repository:

```bash
git clone https://github.com/security007/backdoor_scanner.git
```

Masuk folder:

```bash
cd backdoor_scanner
```

---

## 🚀 Cara Menggunakan

Jalankan scanner dengan:

```bash
python scan.py
```

Hasil scan akan muncul di layar dan dapat disimpan ke file log.

---

## 🧩 Fitur Utama

- 🔍 **Deteksi Pola Berbahaya** (eval, exec, base64 decode, rot13, command execution, dll)
- 🗃️ **Scan Direktori & File** secara rekursif
- ⚠️ **Pendeteksian Shell Backdoor** (PHP, Python, Perl, ASP, JS, dan lainnya)
- 🧰 **Cek Permissions Mencurigakan**
- 🔐 **Deteksi File Obfuscated**
- 📦 **Logging Hasil Scan**
- ⏱️ **Cocok untuk CRON Monitoring**

---

## ⏲️ Jalankan Otomatis via Cronjob

Tambahkan cronjob untuk scan setiap hari:

```bash
crontab -e
```

Kemudian tambahkan baris berikut:

```bash
0 2 * * * /usr/bin/python /path/to/backdoor_scanner/scan.py >> /var/log/backdoor_scan.log 2>&1
```

---

## 🛠️ Requirement

- Python 3.7+
- Linux server environment
- Akses read ke direktori yang akan discan

---

## ⚠️ Catatan

Scanner ini **tidak menggantikan security suite penuh**, tetapi membantu mendeteksi indikasi awal backdoor atau file mencurigakan.

Jika Anda menemukan file berbahaya, lakukan analisa manual atau gunakan antivirus/antimalware pendukung.

---

## 🤝 Kontribusi

Pull request untuk penambahan pola & fitur sangat diterima.

---

## 📜 License

MIT License

---

## ⭐ Support

Bantu dengan memberikan **star** pada repository jika tool ini membantu Anda!
