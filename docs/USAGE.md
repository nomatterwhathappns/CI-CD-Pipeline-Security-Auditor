# Pemakaian dalam tim

Panduan ini membahas pemasangan, pengiriman laporan, pengecualian yang dapat ditinjau, dan penanganan temuan lama. Auditor tetap membaca file secara statis; penilaian risiko akhir memerlukan konteks proyek.

## Memasang CLI

Gunakan Python 3.13. Dari folder utama repo:

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install .
cha-auditor --help
```

Setelah terpasang, `cha-auditor` dapat dipanggil dari folder lain selama virtual environment aktif. Target bawaan tetap `.github/workflows` relatif terhadap folder terminal saat ini. Pemasangan dilakukan dari repo lokal; paket belum dipublikasikan ke PyPI.

Untuk mengembangkan kode, ganti perintah instalasi dengan `python3 -m pip install -e .`. Bentuk `python3 src/auditor.py` dan `python3 -m src.auditor` tetap tersedia. `python3 -m src` juga menjalankan CLI yang sama.

## Laporan dan lokasi sumber

```bash
mkdir -p reports
cha-auditor .github/workflows --format json > reports/audit-report.json
cha-auditor .github/workflows --format sarif > reports/audit-report.sarif
```

JSON menggunakan schema `1.2` dan mempertahankan data temuan, kesalahan, cakupan aturan, dan snapshot advisory. Temuan yang dikecualikan melalui konfigurasi tercatat terpisah pada `suppressed_findings`; `findings_count` menghitung temuan aktif, termasuk temuan baseline yang sudah ada. SARIF ditujukan untuk integrasi penampil analisis statis; menghasilkan file SARIF tidak otomatis mengunggahnya ke layanan apa pun.

Nomor `line` dan `column` menunjuk ke awal scope YAML terkait. Misalnya, temuan untuk script pada langkah ketiga menunjuk ke mapping langkah tersebut. Lokasi ini membantu navigasi tetapi belum selalu menandai karakter ekspresi yang menjadi penyebab. Scope yang menggunakan YAML anchor mengikuti posisi sumber yang disimpan loader.

Nilai kandidat secret tidak dimasukkan ke pesan temuan. Nama file, job, dan metadata kebijakan memang dapat muncul pada laporan; jangan menyimpan secret di sana.

## Mengabaikan aturan atau kasus tertentu

`--ignore CHA005` menonaktifkan aturan untuk seluruh pemindaian. Gunakan hanya bila itu memang kebijakan yang dibutuhkan. Untuk keputusan yang hanya berlaku pada satu kasus, buat file kebijakan JSON, misalnya `.cha-auditor.json` pada folder utama proyek:

```json
{
  "version": 1,
  "ignore": [],
  "suppressions": [
    {
      "rule_id": "CHA009",
      "file": ".github/workflows/release.yml",
      "job": "publish",
      "step": 2,
      "reason": "Pengecualian sementara; tim sedang memverifikasi digest image rilis.",
      "expires": "2027-01-31"
    }
  ]
}
```

Kemudian panggil secara eksplisit:

```bash
cha-auditor .github/workflows --config .cha-auditor.json --format json
```

File konfigurasi tidak dimuat otomatis. Mengubah nama atau menambahkannya ke repo saja tidak mengubah pemindaian tanpa `--config`.

- `version` harus `1`. `ignore` berisi daftar ID aturan yang diabaikan secara global.
- Setiap item `suppressions` memerlukan `rule_id`, `file`, `reason`, dan `expires`. `job` bersifat opsional dan membatasi kecocokan ke job tersebut. `step` memerlukan `job` dan membatasi kecocokan ke nomor langkah tertentu, dimulai dari `1`.
- `file` memakai path atau pola POSIX relatif terhadap folder file konfigurasi. Path absolut dan segmen `..` ditolak. Nama folder dipisahkan dengan `/` termasuk ketika konfigurasi dibuat pada sistem lain. `*` hanya cocok dalam satu komponen path; `**` sebagai komponen dapat melintasi nol atau lebih subfolder. Misalnya, `.github/workflows/*.yml` tidak mencakup file pada subfolder, sedangkan `.github/workflows/**/*.yml` dapat mencakupnya.
- `expires` memakai tanggal `YYYY-MM-DD` menurut UTC dan berlaku sampai tanggal itu secara inklusif. Ganti tanggal contoh sesuai keputusan tim.
- Pengecualian kedaluwarsa menimbulkan kesalahan dengan status `2`, dan temuan yang terkait tidak dianggap sudah dikecualikan.
- `reason` menjelaskan keputusan peninjauan. Hindari nilai secret dan informasi privat yang tidak boleh muncul dalam laporan.

Pengecualian mengubah kebijakan pemeriksaan, bukan memperbaiki workflow. Tinjau siapa yang dapat mengubah file tersebut, alasan pengecualian, dan tenggat penanganannya melalui review repo.

## Menangani temuan lama dengan baseline

Baseline mencatat temuan yang sudah ada agar tim bisa mulai mencegah penambahan masalah sambil memperbaiki temuan lama secara bertahap.

Pertama, simpan dan tinjau baseline:

```bash
mkdir -p reports
cha-auditor .github/workflows --write-baseline reports/baseline.json
```

Kemudian gunakan baseline tersebut dalam pemeriksaan berikutnya:

```bash
cha-auditor .github/workflows --baseline reports/baseline.json --fail-on-findings
```

Temuan yang cocok dengan baseline tetap tampil dengan `baseline_state: "existing"`; temuan lain dianggap baru. Bersama `--fail-on-findings`, temuan baru yang mencapai ambang severity dapat menghasilkan status `1`. Kesalahan pemindaian atau kebijakan tetap lebih diutamakan dan menghasilkan status `2`.

Fingerprint dipakai untuk mencocokkan identitas temuan dan mencakup digest seluruh file workflow. Setiap perubahan isi workflow, termasuk perubahan spasi, membuat seluruh temuan pada file itu dianggap baru. Pilihan konservatif ini mencegah perubahan risiko tersembunyi diterima hanya karena ID aturan dan lokasi masih sama. Temuan yang tidak berubah tetap terlihat sebagai `existing`; status tersebut tidak menyatakan bahwa risiko telah diperbaiki.

Akar identitas path (`source_root`) berasal dari folder file konfigurasi bila `--config` dipakai; tanpa konfigurasi, akarnya adalah folder terminal saat menjalankan auditor. Gunakan akar yang konsisten saat membuat dan memakai baseline. Perubahan akar dapat membuat path temuan berubah dan dianggap baru.

Baseline memuat temuan aktif yang tidak dikecualikan. `--write-baseline` tidak menulis file bila terjadi kesalahan pemindaian atau kebijakan. Jika pemindaian berhasil tetapi gate menghasilkan status `1`, baseline tetap dapat ditulis. Tinjau isinya sebelum dipakai dalam run berikutnya.

Jangan memperbarui baseline otomatis pada setiap CI run: tindakan itu dapat menerima temuan baru tanpa peninjauan. Jika baseline harus dipakai oleh CI, simpan pada lokasi yang dapat diakses CI dan tinjau perubahannya di repo. Folder `reports/` diabaikan oleh Git secara bawaan; gunakan nama yang sengaja dilacak bila baseline menjadi kebijakan bersama.

## Tahapan penerapan yang disarankan

1. Mulai dengan laporan tanpa gate. Periksa temuan secara manual dan catat peringatan keliru maupun kasus yang terlewat.
2. Perbaiki temuan yang jelas. Batasi pengecualian ke kasus tertentu dengan alasan dan tenggat.
3. Bila perlu, tetapkan baseline yang sudah ditinjau. Aktifkan gate untuk temuan baru pada tingkat risiko yang dipilih.
4. Uji kembali ketika GitHub mengubah perilaku platform, versi action diperbarui, atau aturan auditor berubah.

```bash
cha-auditor .github/workflows --config .cha-auditor.json \
  --baseline reports/baseline.json --fail-on-findings --fail-on-severity high
```

Lihat [catatan uji coba lapangan](FIELD_PILOT.md) untuk sumber sampel dan batas evaluasi awal.

Tahapan tersebut adalah pendekatan penerapan proyek ini, bukan sertifikasi atau standar minimal keamanan. Belum ada pengukuran akurasi yang mewakili seluruh variasi repo GitHub Actions.
