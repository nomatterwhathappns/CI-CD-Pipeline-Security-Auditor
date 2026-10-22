# CI/CD Pipeline Security Auditor

Alat Python untuk memeriksa konfigurasi workflow GitHub Actions
dan menandai pola yang perlu ditinjau dari sisi keamanan.

Program membaca file YAML tanpa menjalankan workflow tersebut.

## Aturan pemeriksaan

| Kode | Pemeriksaan |
|---|---|
| GHA001 | Referensi action dari repo GitHub belum memakai SHA commit lengkap |
| GHA002 | Ekspresi data PR tertentu dimasukkan langsung ke dalam run |

GHA002 saat ini memeriksa ekspresi langsung untuk:
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

Melihat bantuan:

```bash
python3 src/auditor.py --help
```

## Membaca hasil

Contoh:

```text
WARNING [GHA001]: contoh.yml: job=build, langkah=1: ...
```

Artinya aturan GHA001 cocok pada langkah pertama dalam job build.

File tanpa temuan tidak menghasilkan baris WARNING,
tetapi tetap dihitung dalam jumlah file yang dipindai.

Status keluar program saat ini:
- 0: proses selesai, termasuk ketika ada temuan.
- 2: terjadi kesalahan yang menghentikan pemindaian.

## Pengujian

```bash
python3 -m unittest discover -s tests -v
```

Pengujian mencakup aturan SHA dan pembacaan workflow contoh.
Saat ini terdapat enam metode pengujian.

## Struktur proyek

- src/: kode auditor.
- fixtures/workflows/: workflow contoh untuk latihan dan pengujian.
- tests/: pengujian otomatis auditor.
- requirements.txt: daftar paket Python yang dibutuhkan.

## Batas kemampuan

- Temuan adalah peringatan untuk ditinjau, bukan bukti pasti adanya celah.
- Tidak ada temuan bukan jaminan bahwa workflow aman.
- GHA001 hanya memeriksa format SHA, bukan keberadaan atau keamanan commit.
- Action lokal dan referensi Docker dilewati oleh aturan GHA001.
- Referensi reusable workflow pada tingkat job belum diperiksa.
- GHA002 memakai pencocokan pola terbatas, bukan analisis lengkap shell.
- Pemeriksaan kebocoran secret dan pemicu berisiko belum dibuat.
