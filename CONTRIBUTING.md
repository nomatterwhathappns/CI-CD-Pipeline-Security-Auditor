# Berkontribusi

Proyek ini mengaudit konfigurasi GitHub Actions sebagai data statis. Jangan mengeksekusi workflow, action, atau script yang sedang diperiksa untuk menentukan apakah inputnya berbahaya.

## Persiapan pengembangan

Gunakan Python 3.13 dan jalankan dari folder utama repo:

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -e .
python3 -m unittest discover -s tests -v
```

Pemasangan editable membuat perintah `cha-auditor` memakai kode kerja saat ini. Perubahan Python langsung terbaca tanpa pemasangan ulang; perubahan metadata atau entry point dapat memerlukan pemasangan ulang.

## Laporan bug

Untuk bug biasa, buka issue dengan versi auditor, versi Python, perintah, hasil yang diharapkan, dan hasil sebenarnya. Sertakan workflow sekecil mungkin dengan nilai rahasia diganti data buatan. Jangan mengunggah token, log privat, atau workflow internal yang tidak boleh dibagikan.

Bedakan peringatan keliru, masalah yang terlewat, dan kegagalan program. Hasil scanner lain dapat membantu pemeriksaan, tetapi bukan bukti tunggal bahwa hasil tersebut benar.

Untuk kerentanan pada auditor, ikuti [SECURITY.md](SECURITY.md).

## Menambah atau memperbaiki aturan

1. Jelaskan masalah, kondisi yang benar-benar dapat dikenali, asumsi, dan batasnya. Gunakan dokumentasi platform, advisory pengelola, atau sumber teknis primer.
2. Pertahankan ID aturan yang sudah ada. Tambahkan metadata registry, panduan perbaikan, serta contoh positif dan negatif. Referensi commit dan digest buatan harus diberi keterangan sebagai ilustrasi.
3. Buat tes yang membuktikan perilaku penting, termasuk kasus yang mirip tetapi seharusnya tidak diperingatkan. Tambahkan regresi untuk bug nyata.
4. Jalankan suite dan audit workflow proyek. Tinjau apakah laporan bisa membocorkan nilai secret atau apakah input dapat menyebabkan crash atau penggunaan sumber daya berlebihan.

```bash
python3 -m unittest discover -s tests -v
cha-auditor .github/workflows --fail-on-findings
```

Untuk perubahan format laporan atau konfigurasi, dokumentasikan kompatibilitas, perubahan status keluar, dan kemungkinan hasil yang berbeda. Tes buatan tidak boleh dilaporkan sebagai ukuran persentase serangan nyata yang berhasil dicegah.

## Evaluasi pada repo nyata

Catat repo, commit, workflow yang diperiksa, versi alat, hasil, dan penilaian manual per temuan. Simpan sumbernya agar evaluasi dapat diulang. Pisahkan sampel pengembangan dari sampel evaluasi bila mengukur akurasi. Jangan menjalankan workflow tak tepercaya dalam proses evaluasi.

## Lisensi

Mulai versi 1.2.1, kode proyek menggunakan [GNU GPL versi 3 saja — GPL-3.0-only](LICENSE). Kontribusikan hanya materi yang memang boleh Anda bagikan dengan ketentuan tersebut, dan pertahankan pemberitahuan lisensi dari komponen pihak ketiga bila relevan. Riwayat versi MIT dan atribusi komponen dijelaskan pada [NOTICE.md](NOTICE.md).
