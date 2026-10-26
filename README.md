# CI/CD Pipeline Security Auditor

Alat Python untuk memeriksa konfigurasi workflow GitHub Actions
dan menandai pola yang perlu ditinjau dari sisi keamanan.

Program membaca file YAML tanpa menjalankan workflow tersebut.

## Aturan pemeriksaan

| Kode | Pemeriksaan |
|---|---|
| CHA001 | Referensi action dari repo GitHub belum memakai SHA commit lengkap |
| CHA002 | Ekspresi data PR tertentu dimasukkan langsung ke dalam run |
| CHA003 | Deklarasi permissions: write-all pada tingkat workflow atau job |

CHA002 saat ini memeriksa ekspresi langsung untuk:
- github.event.pull_request.title
- github.event.pull_request.body
- github.event.pull_request.head.ref
- github.event.pull_request.head.label

Perintah run satu baris maupun beberapa baris dapat diperiksa.

## Persiapan

Proyek dikembangkan menggunakan Python 3.13.5.

Jalankan dari folder utama proyek:

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
```

## Penggunaan

Memindai satu file:

```bash
python3 src/auditor.py fixtures/workflows/insecure-example.yml
```

Memindai folder beserta subfoldernya:

```bash
python3 src/auditor.py fixtures/workflows
```

Memindai workflow proyek lain:

```bash
python3 src/auditor.py /lokasi/proyek-lain/.github/workflows
```

Ganti lokasi contoh tersebut dengan lokasi proyek yang ingin diperiksa.

Tanpa argumen lokasi, program memeriksa .github/workflows
relatif terhadap folder Terminal saat ini.

Untuk menghasilkan status 1 ketika ada temuan:

```bash
python3 src/auditor.py fixtures/workflows --fail-on-findings
```

Opsi ini berguna agar proses otomatis dapat menganggap temuan
sebagai kegagalan pemeriksaan.

Melihat bantuan:

```bash
python3 src/auditor.py --help
```

## Membaca hasil

Contoh:

```text
WARNING [CHA001]: contoh.yml: job=build, langkah=1: ...
```

Artinya aturan CHA001 cocok pada langkah pertama dalam job build.

File tanpa temuan tidak menghasilkan baris WARNING,
tetapi tetap dihitung dalam jumlah file yang dipindai.

Status keluar program:
- 0: pemindaian selesai; tanpa --fail-on-findings, temuan tidak mengubah status.
- 1: ada temuan dan --fail-on-findings dipakai.
- 2: terjadi kesalahan yang menghentikan pemindaian.

## Pengujian

```bash
python3 -m unittest discover -s tests -v
```

Pengujian mencakup aturan SHA, data PR dalam run,
izin workflow dan job, serta opsi dan status keluar program.
Saat ini terdapat 14 metode pengujian.

## Struktur proyek

- src/: kode auditor.
- fixtures/workflows/: workflow contoh untuk latihan dan pengujian.
- tests/: pengujian otomatis auditor.
- requirements.txt: daftar paket Python yang dibutuhkan.

## Batas kemampuan

- Temuan adalah peringatan untuk ditinjau, bukan bukti pasti adanya celah.
- Tidak ada temuan bukan jaminan bahwa workflow aman.
- CHA001 hanya memeriksa format SHA, bukan keberadaan atau keamanan commit.
- Action lokal dan referensi Docker dilewati oleh aturan CHA001.
- Referensi reusable workflow pada tingkat job belum diperiksa.
- CHA002 memakai pencocokan pola terbatas, bukan analisis lengkap shell.
- Pemeriksaan kebocoran secret dan pemicu berisiko belum dibuat.
- CHA003 hanya menandai deklarasi write-all secara langsung; izin efektif dan kebutuhan izin belum dianalisis.

### Laporan JSON

Menampilkan laporan JSON:

```bash
python3 src/auditor.py fixtures/workflows --format json
```

Menyimpan laporan:

```bash
mkdir -p reports
python3 src/auditor.py fixtures/workflows --format json > reports/audit-report.json
```

Isi laporan:
- files_scanned: jumlah file yang berhasil diperiksa.
- findings_count: jumlah temuan.
- findings: daftar detail temuan.
- errors: daftar kegagalan pemindaian.

Nilai null pada job atau step berarti lokasi tersebut tidak berlaku.

Jika ada kegagalan pemindaian, status keluar adalah 2,
termasuk ketika laporan juga berisi temuan keamanan.
