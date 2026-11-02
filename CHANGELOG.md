# Catatan perubahan

## 1.0.0 — 2026-11-02

Rilis dengan 20 aturan statis untuk konfigurasi GitHub Actions, laporan teks dan JSON, serta pemeriksaan otomatis di CI.

### Pemeriksaan

- CHA001–CHA003: referensi action dan reusable workflow, ekspresi data tak tepercaya dalam script, serta deklarasi `permissions: write-all`.
- CHA004–CHA010: kandidat kredensial literal, pembagian secret, serialisasi seluruh secret, respons unduhan yang langsung dijalankan, verifikasi HTTPS, digest container, dan password registry.
- CHA011–CHA017: runner self-hosted pada PR, checkout dan artifact dari konteks tak tepercaya, upload file sensitif, cache, environment/output file, dan pencarian program melalui PATH.
- CHA018–CHA020: kondisi `if`, otorisasi berbasis substring, dan pencocokan advisory action.
- Metadata severity, confidence, serta saran perbaikan untuk temuan. Severity dan confidence merupakan klasifikasi proyek, bukan skor CVSS.

### CLI dan laporan

- Mempertahankan `python3 src/auditor.py` dan menyediakan `python3 -m src.auditor`.
- Target file atau folder, dengan bawaan `.github/workflows`.
- `--format text|json`, laporan JSON schema **1.1**, versi auditor, aturan aktif/diabaikan, dan metadata snapshot advisory.
- `--ignore` berkoma atau berulang, `--list-rules`, dan `--version`.
- `--fail-on-findings` dengan ambang `--fail-on-severity`. Ambang mengatur status keluar tanpa menyembunyikan temuan.
- Status `0` untuk pemeriksaan yang tidak gagal menurut kebijakan, `1` untuk temuan yang mencapai ambang, dan `2` untuk kesalahan. Kesalahan lebih diutamakan daripada temuan; pemindaian folder berlanjut setelah kegagalan satu file.

### Input dan snapshot advisory

- Pembacaan YAML sebagai data tanpa menjalankan isi workflow atau script. Pesan kesalahan tidak menampilkan konteks YAML, dan nilai kandidat kredensial tidak disalin ke temuan.
- Batas workflow 2 MiB, kedalaman YAML 50, dan 50 referensi alias. Anchor/alias didukung dalam batas tersebut; merge key `<<`, kunci berulang, dan bentuk input yang tidak valid ditolak.
- Penanganan kesalahan untuk target symlink, ekstensi tidak didukung, dan folder tanpa YAML. Penelusuran melewati symlink, `.git`, `.venv`, `node_modules`, dan `__pycache__`.
- Snapshot offline terbatas pada tiga advisory terverifikasi, diperiksa pada **2026-11-02**. Versi stabil lengkap dan SHA berbahaya yang terdaftar dapat dicocokkan; tag bergerak, prerelease, dan SHA lain tetap belum dapat dipastikan.
- Catatan pemulihan tag `tj-actions/changed-files` agar kecocokan rentang versi tidak disamakan dengan bukti bahwa tag saat ini berbahaya.
- `--advisory-file` untuk memakai snapshot lokal tervalidasi yang menggantikan snapshot bawaan secara penuh.

### Contoh, dokumentasi, dan CI

- 40 contoh YAML statis, satu pasangan `bad`/`good` per aturan, dengan manifest dan sumber. Semua contoh `good` diperiksa terhadap 20 aturan.
- Pengujian positif/negatif untuk aturan, laporan dan status CLI, konfigurasi, serta input yang salah.
- Panduan aturan berbahasa Indonesia dan README dengan alur instalasi, penggunaan, serta batas pemeriksaan.
- Workflow CI untuk menjalankan pengujian dan audit proyek. Laporan JSON diunggah sebagai artifact selama tujuh hari; upload tetap dicoba setelah kegagalan dan tidak mengubah kegagalan audit menjadi keberhasilan.
- Pemisahan CLI, engine, registry aturan, modul pemeriksaan, dan data advisory untuk pengembangan berikutnya.
