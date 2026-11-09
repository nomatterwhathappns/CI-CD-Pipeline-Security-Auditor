# Catatan perubahan

## 1.1.0 — 2026-11-09

Perbaikan akurasi dan alat penerapan bertahap untuk GitHub Actions. Status versi ini tetap cocok untuk uji coba dengan peninjauan manusia; kelulusan tes belum mengukur akurasi pada seluruh repo nyata.

### Pemeriksaan dan lokasi

- CHA001 mengenali referensi repo sendiri `$/...` yang mengikuti commit workflow berjalan, sehingga bentuk tersebut tidak diperingatkan sebagai referensi remote tanpa SHA.
- CHA004 mengenali tiga bentuk metadata gh-aw secara terbatas, berdasarkan sepuluh peringatan keliru pada uji workflow publik; nilai kandidat lain tetap diperiksa.
- Lokasi `line` dan `column` membantu menavigasi scope workflow, job, atau langkah yang menghasilkan temuan. Lokasi menunjuk ke awal scope; belum selalu tepat pada token penyebab.
- CHA021 memeriksa opt-in environment untuk workflow command yang tidak aman. CHA022 menandai mode privileged eksplisit pada container job atau service. Lihat panduan aturan tambahan untuk bentuk yang didukung dan batasnya.

### Pemakaian dan kebijakan

- Paket lokal dapat dipasang dengan `pip install .`; perintah `cha-auditor` disediakan, data advisory ikut terpasang, dan entry point lama tetap tersedia.
- Laporan SARIF melengkapi laporan teks dan JSON. Pembuatan file tidak otomatis mengunggah laporan ke GitHub Code Scanning.
- Konfigurasi JSON eksplisit menyediakan pengabaian aturan serta pengecualian berdasarkan aturan, pola file, job, dan langkah, disertai alasan serta kedaluwarsa. Pengecualian kedaluwarsa adalah kesalahan kebijakan.
- Baseline dapat ditulis dan dimuat secara eksplisit. Temuan lama tetap terlihat, sementara gate dapat difokuskan pada temuan baru. Baseline perlu peninjauan dan tidak diperbarui otomatis.
- Panduan pemasangan, penerapan dalam tim, kontribusi, dan pelaporan keamanan ditambahkan. Kode proyek menggunakan lisensi MIT yang disertakan dalam paket distribusi.

### Evaluasi awal

- 56 workflow dari tujuh repo publik diverifikasi memakai Git blob SHA dan berhasil dipindai tanpa kesalahan pembacaan. Sepuluh peringatan metadata yang keliru diperbaiki; 26 peringatan konfigurasi tetap memerlukan peninjauan.
- Manifest, ringkasan hasil, dan script evaluasi yang dapat dijalankan ulang disediakan. Sampel digunakan untuk pengembangan perbaikan ini dan belum menjadi pengukuran akurasi independen atau kelengkapan deteksi.

Snapshot advisory tetap terbatas pada tiga entri offline yang diperiksa pada 2026-11-02. Perubahan ini tidak menambahkan pemantauan kerentanan otomatis, verifikasi GitHub lockfile, atau analisis lengkap script dan dependensi action.

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
