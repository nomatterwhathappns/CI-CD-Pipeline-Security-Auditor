# CI/CD Pipeline Security Auditor

Auditor statis GitHub Actions berbasis Python. Versi **1.0.0** menyediakan **20 aturan CHA001–CHA020** untuk menandai konfigurasi yang perlu ditinjau sebelum workflow digunakan atau perubahan digabungkan.

Program membaca YAML sebagai data. Isi workflow, script, action, dan artifact tidak dijalankan. Auditor dapat dipakai dari terminal atau sebagai pemeriksaan di CI.

## Persiapan

Gunakan **Python 3.13**. Periksa versi dengan `python3 --version`, lalu:

```bash
git clone https://github.com/nomatterwhathappns/CI-CD-Pipeline-Security-Auditor.git
cd CI-CD-Pipeline-Security-Auditor
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
```

Jalankan perintah berikut dari folder utama proyek dengan virtual environment aktif.

## Mulai memindai

Satu file contoh:

```bash
python3 src/auditor.py fixtures/workflows/insecure-example.yml
```

Folder beserta subfoldernya:

```bash
python3 src/auditor.py fixtures/workflows
```

Workflow proyek lain:

```bash
python3 src/auditor.py /lokasi/proyek-lain/.github/workflows
```

Ganti lokasi contoh dengan folder workflow yang ingin diperiksa. Hanya file `.yml` dan `.yaml` yang ditemukan dalam folder yang dipindai.

Tanpa argumen lokasi, targetnya adalah `.github/workflows` relatif terhadap folder terminal saat ini. Bentuk modul juga tersedia:

```bash
python3 -m src.auditor .github/workflows
python3 src/auditor.py --help
python3 src/auditor.py --version
```

## Aturan yang tersedia

| Kode | Pemeriksaan | Severity |
|---|---|---|
| CHA001 | Referensi action atau reusable workflow belum memakai SHA commit lengkap | medium |
| CHA002 | Ekspresi data tak tepercaya menjadi bagian kode `run` atau `actions/github-script` | high |
| CHA003 | Deklarasi langsung `permissions: write-all` pada workflow atau job | medium |
| CHA004 | Kandidat kredensial literal dalam `env` workflow, job, atau langkah | high |
| CHA005 | Reusable workflow menerima seluruh secret melalui `secrets: inherit` | medium |
| CHA006 | Seluruh konteks secret diserialisasikan dengan `toJSON(secrets)` | high |
| CHA007 | Respons unduhan HTTP(S) dipipe langsung ke `bash` atau `sh` | high |
| CHA008 | Transfer HTTPS dengan `curl` mematikan verifikasi sertifikat | high |
| CHA009 | Image job, service, atau action Docker belum memakai digest SHA-256 lengkap | medium |
| CHA010 | Password registry container atau service ditulis sebagai nilai literal | high |
| CHA011 | Job PR dapat memakai runner self-hosted | high |
| CHA012 | Checkout kode PR diikuti eksekusi dalam konteks `pull_request_target` | critical |
| CHA013 | Artifact dari `workflow_run` mencapai lokasi kode yang kemudian dijalankan | critical |
| CHA014 | Pola upload artifact dapat menyertakan file sensitif | high |
| CHA015 | Kode atau data tak tepercaya dapat memengaruhi cache dengan izin tulis istimewa | high |
| CHA016 | Data tak tepercaya ditulis ke `GITHUB_ENV` atau `GITHUB_OUTPUT` tanpa pembatasan yang dikenali | high |
| CHA017 | Data tak tepercaya memengaruhi direktori pencarian program melalui `GITHUB_PATH` | high |
| CHA018 | Penulisan `if` dapat membentuk string yang dianggap benar | high |
| CHA019 | Pengecekan identitas memakai pencocokan substring | high |
| CHA020 | Referensi action cocok dengan snapshot advisory lokal | high |

`severity` adalah tingkat risiko yang ditetapkan proyek. `confidence` menunjukkan keyakinan terhadap kecocokan pola yang dikenali. Keduanya bukan skor CVSS atau bukti bahwa eksploitasi telah terjadi. Misalnya, CHA004 menandai kandidat kredensial, sedangkan CHA005 meminta peninjauan atas pembagian secret yang mungkin memang disengaja.

Lihat [panduan setiap aturan](docs/RULES.md) untuk kondisi pemicu, batas pemeriksaan, contoh, perbaikan, dan sumbernya. Daftar aturan juga tersedia melalui CLI:

```bash
python3 src/auditor.py --list-rules
python3 src/auditor.py --list-rules --format json
```

## Membaca hasil dan menentukan status CI

Format bawaan adalah teks:

```text
WARNING [CHA001]: contoh.yml: job=build, langkah=1: ...
```

Lokasi tersebut berarti temuan berada pada langkah pertama job `build`. File tanpa temuan tetap dihitung sebagai file yang berhasil diperiksa.

Untuk mengembalikan status gagal ketika ada temuan:

```bash
python3 src/auditor.py .github/workflows --fail-on-findings
```

Untuk menggagalkan CI hanya pada tingkat `high` atau `critical`:

```bash
python3 src/auditor.py .github/workflows --fail-on-findings --fail-on-severity high
```

Pilihan ambang adalah `low`, `medium`, `high`, dan `critical`, dengan bawaan `low`. `--fail-on-severity` hanya mengatur status keluar bersama `--fail-on-findings`. Temuan di bawah ambang tetap terlihat dalam laporan.

| Status | Arti |
|---|---|
| `0` | Pemindaian berhasil dan tidak ada temuan yang menggagalkan pemeriksaan. Tanpa `--fail-on-findings`, temuan tetap menghasilkan status `0`. |
| `1` | `--fail-on-findings` dipakai dan setidaknya satu temuan mencapai ambang severity. |
| `2` | Ada kesalahan input, konfigurasi, atau pemindaian. Status ini lebih diutamakan daripada temuan. |

Jika satu file dalam folder gagal diperiksa, file berikutnya tetap diproses. Laporan dapat berisi temuan sekaligus kesalahan; status akhirnya tetap `2`.

Aturan dapat diabaikan dengan daftar berkoma atau opsi berulang:

```bash
python3 src/auditor.py .github/workflows --ignore CHA005,CHA009 --ignore CHA001
```

Temuan dari aturan tersebut tidak dimasukkan ke laporan. Pilihan aturan aktif dan yang diabaikan tercatat dalam metadata JSON agar keputusan pemeriksaan dapat ditinjau. Kode aturan yang tidak dikenal menghasilkan kesalahan argumen.

## Laporan JSON

Tampilkan JSON:

```bash
python3 src/auditor.py fixtures/workflows --format json
```

Simpan laporan:

```bash
mkdir -p reports
python3 src/auditor.py fixtures/workflows --format json > reports/audit-report.json
python3 -m json.tool reports/audit-report.json
```

Folder `reports/` sudah diabaikan oleh Git. Menambahkan `--fail-on-findings` tetap menyimpan laporan saat ada temuan, sekaligus dapat menghasilkan status `1`.

Laporan memakai `schema_version: "1.1"`:

| Field | Isi |
|---|---|
| `auditor_version` | Versi program yang menghasilkan laporan. |
| `files_scanned` | Jumlah file yang berhasil diperiksa; file yang gagal tidak dihitung. |
| `findings_count`, `findings` | Jumlah dan detail temuan setelah aturan yang diabaikan diterapkan. |
| `errors` | Lokasi file atau konfigurasi yang gagal diperiksa beserta pesan ringkasnya. |
| `rules_enabled`, `rules_ignored` | Daftar aturan aktif dan aturan yang diabaikan. |
| `advisory_snapshot` | Tanggal, cakupan, dan jumlah entri snapshot advisory yang digunakan. |

Setiap temuan memuat `rule_id`, `file`, `job`, `step`, `message`, `severity`, `confidence`, dan `remediation`, ditambah detail lokasi atau advisory yang relevan. `job` atau `step` bernilai `null` jika lokasi tersebut tidak berlaku.

Kesalahan pemindaian tetap dilaporkan sebagai JSON. Kesalahan argumen CLI ditangani oleh `argparse` dan dapat tampil sebagai teks di stderr, termasuk ketika `--format json` dipilih.

## Cakupan advisory CHA020

Snapshot bawaan diperiksa pada **2026-11-02** dan hanya berisi **tiga advisory terverifikasi** untuk `tj-actions/changed-files`, `actions/download-artifact`, dan `dawidd6/action-download-artifact`. Snapshot ini bersifat offline dan tidak diperbarui otomatis.

CHA020 membandingkan versi stabil lengkap, seperti `v4.1.2` atau `4.1.2`, serta SHA berbahaya yang secara eksplisit terdaftar. Tag bergerak seperti `v4` atau `v4.1`, prerelease, dan SHA lain yang tidak dikenal tetap belum dapat dipastikan dan dilewati. Tidak adanya temuan CHA020 tidak menyatakan bahwa action aman.

Untuk insiden `tj-actions/changed-files`, advisory menjelaskan bahwa tag terdampak kemudian dipulihkan. Kecocokan rentang versi saja tidak membuktikan bahwa tag saat ini menunjuk ke kode berbahaya; tinjau riwayat run dan commit yang benar-benar digunakan.

Snapshot sendiri dapat diberikan melalui:

```bash
python3 src/auditor.py .github/workflows --format json --advisory-file /lokasi/snapshot.json
```

File tersebut **menggantikan seluruh snapshot bawaan**, bukan digabungkan dengannya. Format dan validasinya dijelaskan pada [panduan CHA020](docs/RULES.md#memakai-snapshot-advisory-sendiri).

## Belajar satu aturan setiap kali

Folder [fixtures/rules](fixtures/rules) berisi 40 file: satu contoh `bad` dan satu contoh `good` untuk masing-masing aturan. Mulai dari satu pasangan:

```bash
python3 src/auditor.py fixtures/rules/CHA001-bad.yml
python3 src/auditor.py fixtures/rules/CHA001-good.yml
```

[Manifest contoh](fixtures/rules/manifest.json) memetakan file, aturan sasaran, catatan, sumber, dan asal referensi yang diverifikasi. Pengujian memeriksa pemicu setiap aturan dan memastikan semua contoh `good` tidak menghasilkan temuan dari 20 aturan saat ini.

Contoh dipakai sebagai data statis dan disimpan di luar `.github/workflows`. Digest image, beberapa path, dan pemanggilan workflow dalam contoh bersifat ilustratif; contoh tersebut bukan paket workflow siap dijalankan. CHA001 memeriksa format SHA dan tidak memverifikasi keberadaan atau keamanan commit.

## Pengujian dan CI proyek

Jalankan suite pengujian:

```bash
python3 -m unittest discover -s tests -v
```

Suite mencakup aturan positif dan negatif, matriks contoh, input YAML yang salah, pembatasan parser, penyamaran nilai kredensial, laporan JSON, pengabaian aturan, ambang severity, dan status keluar.

Workflow **Auditor CI** menjalankan pengujian serta audit atas `.github/workflows`. Laporan disimpan sebagai artifact **workflow-audit-report** selama **tujuh hari**. Unduh melalui halaman Actions, pilih run, lalu buka bagian Artifacts.

Langkah upload memakai `if: always()` agar penyimpanan tetap dicoba setelah kegagalan. Laporan tersedia bila file berhasil dihasilkan. Upload yang berhasil tidak mengubah kegagalan audit menjadi keberhasilan CI.

## Struktur kode

| Lokasi | Tanggung jawab |
|---|---|
| `src/auditor.py` | CLI, pencarian file, format laporan, dan status keluar. |
| `src/engine.py` | Pembacaan dan validasi YAML, pengumpulan temuan, CHA001–CHA003. |
| `src/rules/basic.py` | CHA004–CHA010. |
| `src/rules/trust.py` | CHA011–CHA017. |
| `src/rules/guards.py` | CHA018–CHA020 dan validasi snapshot advisory. |
| `src/rules/common.py` | Konteks aturan dan helper bersama. |
| `src/registry.py` | Identitas, severity, perbaikan, dan referensi aturan. |
| `src/data/advisories.json` | Snapshot advisory bawaan. |
| `fixtures/`, `tests/`, `docs/` | Contoh statis, pengujian, dan panduan. |

## Batas pemeriksaan

- Auditor mengenali pola statis terbatas. Parser shell, alur data, kondisi eksekusi, dan konfigurasi GitHub tidak dianalisis secara lengkap. Kasus di luar pola yang didukung tetap belum dapat dipastikan.
- Temuan memerlukan peninjauan. Tidak adanya temuan bukan jaminan keamanan, dan SHA atau digest yang dipatok tetap perlu ditinjau serta diperbarui.
- Pemeriksaan script dibatasi pada bentuk yang dikenali. Contohnya, CHA007–CHA008 tidak menyelesaikan URL dinamis, alias atau fungsi shell, heredoc, dan sejumlah opsi downloader yang tidak dikenali.
- CHA003 mendeteksi deklarasi `write-all` secara langsung; kebutuhan dan izin token efektif tidak dihitung secara lengkap.
- Kandidat kredensial CHA004 dan CHA010 tidak disalin ke temuan. Kesalahan YAML tidak menampilkan cuplikan konteks file yang mungkin berisi secret.
- Ukuran workflow dibatasi **2 MiB**, kedalaman YAML maksimal **50**, dan referensi alias maksimal **50**. Anchor dan alias didukung dalam batas tersebut; YAML merge key `<<` ditolak. Kunci berulang, termasuk `on`, ditolak.
- Target symlink, file dengan ekstensi tidak didukung, dan folder tanpa YAML menghasilkan status `2`. Saat menelusuri folder, entri symlink serta folder `.git`, `.venv`, `node_modules`, dan `__pycache__` dilewati.

Perubahan versi dicatat pada [CHANGELOG.md](CHANGELOG.md).
