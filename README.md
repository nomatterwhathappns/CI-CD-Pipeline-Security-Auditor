# CI/CD Pipeline Security Auditor

Auditor statis GitHub Actions berbasis Python. Versi **1.2.1** menyediakan **23 aturan CHA001–CHA023** untuk menandai konfigurasi yang perlu ditinjau sebelum workflow digunakan atau perubahan digabungkan.

Program membaca YAML sebagai data. Isi workflow, script, action, dan artifact tidak dijalankan. Auditor dapat dipakai dari terminal atau sebagai pemeriksaan di CI.

CHA023 menelusuri beberapa perpindahan data di dalam workflow, sehingga data PR yang sudah dipindahkan melalui environment atau output tetap dapat ditandai saat dimasukkan kembali ke kode script. Mode `--deep` memperluas pemeriksaan ke composite action dan reusable workflow lokal yang dirujuk. Pemeriksaan ini berbasis aturan dan penelusuran data; tidak memanggil model AI.

Versi ini cocok untuk uji coba sebagai pemeriksaan tambahan pada proyek nyata. Akurasi pada kumpulan besar repo yang dinilai secara independen belum terukur. Jumlah aturan dan kelulusan tes bukan ukuran persentase serangan yang dapat dicegah.

## Persiapan

Gunakan **Python 3.13**. Periksa versi dengan `python3 --version`, lalu:

```bash
git clone https://github.com/nomatterwhathappns/CI-CD-Pipeline-Security-Auditor.git
cd CI-CD-Pipeline-Security-Auditor
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install .
```

Pemasangan tersebut menyediakan perintah **`cha-auditor`**, sehingga lokasi kode program tidak perlu ditulis setiap kali memindai. Dari terminal dengan virtual environment aktif:

```bash
cha-auditor --version
cha-auditor /lokasi/proyek-lain/.github/workflows
```

Paket belum dipublikasikan ke PyPI; `pip install .` memasang kode dari folder repo yang sudah diambil. Mulai versi 1.2.1, kode proyek menggunakan [GNU GPL versi 3 saja — GPL-3.0-only](LICENSE). Versi MIT yang sudah diterbitkan tetap mempertahankan izinnya; lihat [pemberitahuan dan riwayat lisensi](NOTICE.md).

Perintah lama `python3 src/auditor.py ...` tetap tersedia dari folder utama repo. Jika hanya ingin menjalankan bentuk lama tanpa memasang CLI, pasang dependensi dengan `python3 -m pip install -r requirements.txt`. Untuk mengembangkan kode, gunakan `python3 -m pip install -e .`.

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
| CHA021 | Environment mengaktifkan kembali workflow command yang tidak aman | high |
| CHA022 | Container job atau service meminta mode privileged secara eksplisit | high |
| CHA023 | Data tak tepercaya mencapai kode script melalui environment, output, atau input yang ditelusuri | high |

`severity` adalah tingkat risiko yang ditetapkan proyek. `confidence` menunjukkan keyakinan terhadap kecocokan pola yang dikenali. Keduanya bukan skor CVSS atau bukti bahwa eksploitasi telah terjadi. Misalnya, CHA004 menandai kandidat kredensial, sedangkan CHA005 meminta peninjauan atas pembagian secret yang mungkin memang disengaja.

Lihat [panduan CHA001–CHA020](docs/RULES.md), [panduan CHA021–CHA022](docs/ADDITIONAL_RULES.md), dan [panduan penelusuran data CHA023](docs/DATAFLOW.md) untuk kondisi pemicu, batas pemeriksaan, contoh, perbaikan, dan sumbernya. Daftar aturan juga tersedia melalui CLI:

```bash
python3 src/auditor.py --list-rules
python3 src/auditor.py --list-rules --format json
```

## Menelusuri file yang dipanggil workflow

Dari folder utama proyek yang ingin diperiksa, setelah CLI auditor terpasang:

```bash
cha-auditor .github/workflows --deep --repo-root . --format json
```

`--repo-root` membatasi akar repo yang boleh dibaca. Mode `--deep` mengikuti referensi lokal `./` dan `$/` untuk composite action dan reusable workflow. File yang dirujuk dibaca sebagai data; tidak ada checkout, unduhan action, atau eksekusi script. Referensi remote serta bentuk yang belum didukung dicatat sebagai belum dianalisis.

Laporan menyertakan cakupan penelusuran dan bagian yang belum terselesaikan. Pemindaian tanpa temuan masih dapat memiliki cakupan yang tidak lengkap. Panduan penggunaan, batas ukuran/penelusuran, konteks pemanggil, dan interpretasi hasil ada di [panduan analisis mendalam](docs/DEEP_ANALYSIS.md).

## Membaca hasil dan menentukan status CI

Format bawaan adalah teks:

```text
WARNING [CHA001]: contoh.yml: job=build, langkah=1: ...
```

Lokasi tersebut berarti temuan berada pada langkah pertama job `build`. Field `line` dan `column` pada laporan menunjuk ke awal scope YAML terkait, yaitu workflow, job, atau langkah; lokasinya belum selalu tepat pada token penyebab. File tanpa temuan tetap dihitung sebagai file yang berhasil diperiksa.

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

## Laporan JSON dan SARIF

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

Laporan JSON memakai `schema_version: "1.3"` dan mempertahankan field inti dari versi sebelumnya:

| Field | Isi |
|---|---|
| `schema_version`, `auditor_version` | Versi struktur JSON dan program yang menghasilkan laporan. |
| `files_scanned` | Jumlah file yang berhasil diperiksa; file yang gagal tidak dihitung. |
| `findings_count`, `findings` | Jumlah dan detail temuan aktif setelah pengabaian aturan dan pengecualian, termasuk temuan lama pada baseline. |
| `errors` | Lokasi file atau konfigurasi yang gagal diperiksa beserta pesan ringkasnya. |
| `rules_enabled`, `rules_ignored` | Daftar aturan aktif dan aturan yang diabaikan. |
| `advisory_snapshot` | Tanggal, cakupan, dan jumlah entri snapshot advisory yang digunakan. |
| `suppressed_findings_count`, `suppressed_findings` | Temuan yang dikecualikan secara terarah, dengan alasan dan tanggal kedaluwarsa. |
| `existing_findings_count`, `new_findings_count` | Jumlah temuan aktif yang sudah ada dalam baseline dan jumlah temuan baru. |
| `policy`, `baseline`, `source_root` | File kebijakan/baseline yang dipakai dan akar untuk identitas path sumber. |
| `analysis` | Mode analisis, cakupan penelusuran file lokal, serta referensi/bagian yang belum dianalisis. |

Setiap temuan memuat `rule_id`, `file`, `job`, `step`, `message`, `severity`, `confidence`, dan `remediation`, ditambah lokasi sumber serta detail advisory yang relevan. `line`, `column`, dan `location_scope` membantu menavigasi awal scope YAML. `source_digest` adalah SHA-256 seluruh isi file, sedangkan `fingerprint` mengikat identitas temuan untuk baseline. Bukti CHA023 memakai `dataflow_trace`; temuan deep dapat menyertakan `analysis_call_path`, `analysis_call_paths`, dan `analysis_digest`. Field tersebut memuat identitas lokasi dan digest, bukan nilai input mentah. `baseline_state` bernilai `existing` atau `new` pada laporan CLI yang selesai diproses. `job` atau `step` bernilai `null` jika lokasi tersebut tidak berlaku.

Kesalahan pemindaian tetap dilaporkan sebagai JSON. Kesalahan argumen CLI ditangani oleh `argparse` dan dapat tampil sebagai teks di stderr, termasuk ketika `--format json` dipilih.

Laporan SARIF tersedia untuk integrasi dengan penampil hasil analisis yang mendukung format tersebut:

```bash
mkdir -p reports
cha-auditor .github/workflows --format sarif > reports/audit-report.sarif
```

Perintah tersebut menghasilkan file; perintah ini sendiri tidak mengunggah hasil ke GitHub Code Scanning. Upload memerlukan langkah CI dan izin yang sesuai.

## Pengecualian terarah dan baseline

`--config` memuat kebijakan JSON yang disebut secara eksplisit. Pengecualian dapat dibatasi menurut aturan, pola file, job, dan langkah, disertai alasan serta tanggal kedaluwarsa. Ini membantu meninjau keputusan yang disengaja tanpa mengabaikan satu aturan untuk seluruh proyek.

`--baseline` menandai temuan yang sudah tercatat, sehingga gate dapat difokuskan pada temuan baru. Temuan lama tetap dilaporkan; baseline bukan pernyataan bahwa temuan lama aman. Fingerprint mencakup seluruh isi file workflow, sehingga perubahan isi apa pun membuat temuan pada file itu dianggap baru.

```bash
mkdir -p reports
cha-auditor .github/workflows --write-baseline reports/baseline.json
cha-auditor .github/workflows --baseline reports/baseline.json --fail-on-findings
```

Tinjau baseline sebelum menjadikannya kebijakan CI. Memperbarui baseline dapat membuat temuan baru dianggap sudah diterima. Panduan format konfigurasi, alasan, kedaluwarsa, dan batas fingerprint ada di [panduan pemakaian tim](docs/USAGE.md).

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

Folder [fixtures/rules](fixtures/rules) menyediakan pasangan contoh `bad` dan `good` untuk setiap aturan. Mulai dari satu pasangan:

```bash
python3 src/auditor.py fixtures/rules/CHA001-bad.yml
python3 src/auditor.py fixtures/rules/CHA001-good.yml
```

[Manifest contoh](fixtures/rules/manifest.json) memetakan file, aturan sasaran, catatan, sumber, dan asal referensi yang diverifikasi. Pengujian memeriksa pemicu setiap aturan dan memastikan semua contoh `good` tidak menghasilkan temuan dari seluruh aturan saat ini.

Contoh dipakai sebagai data statis dan disimpan di luar `.github/workflows`. Digest image, beberapa path, dan pemanggilan workflow dalam contoh bersifat ilustratif; contoh tersebut bukan paket workflow siap dijalankan. CHA001 memeriksa format SHA dan tidak memverifikasi keberadaan atau keamanan commit.

## Pengujian dan CI proyek

Jalankan suite pengujian:

```bash
python3 -m unittest discover -s tests -v
```

Suite mencakup aturan positif dan negatif, matriks contoh, input YAML yang salah, pembatasan parser, penyamaran nilai kredensial, laporan JSON, pengabaian aturan, ambang severity, dan status keluar.

Workflow **Auditor CI** memasang paket, menjalankan pengujian, serta mengaudit `.github/workflows`. Laporan JSON dan SARIF disimpan sebagai artifact **workflow-audit-report** selama **tujuh hari**. Unduh melalui halaman Actions, pilih run, lalu buka bagian Artifacts.

Langkah upload memakai `if: always()` agar penyimpanan tetap dicoba setelah kegagalan. Laporan tersedia bila file berhasil dihasilkan. Upload yang berhasil tidak mengubah kegagalan audit menjadi keberhasilan CI.

## Struktur kode

| Lokasi | Tanggung jawab |
|---|---|
| `src/auditor.py` | CLI, pencarian file, format laporan, dan status keluar. |
| `src/engine.py` | Pembacaan dan validasi YAML, pengumpulan temuan, CHA001–CHA003. |
| `src/rules/basic.py` | CHA004–CHA010. |
| `src/rules/trust.py` | CHA011–CHA017. |
| `src/rules/guards.py` | CHA018–CHA020 dan validasi snapshot advisory. |
| `src/rules/additional.py` | CHA021–CHA022. |
| `src/rules/common.py` | Konteks aturan dan helper bersama. |
| `src/analysis/dataflow.py` | Penelusuran data terbatas dan CHA023. |
| `src/analysis/graph.py` | Penelusuran composite action dan reusable workflow lokal pada mode `--deep`. |
| `src/registry.py` | Identitas, severity, perbaikan, dan referensi aturan. |
| `src/data/advisories.json` | Snapshot advisory bawaan. |
| `fixtures/`, `tests/`, `docs/` | Contoh statis, pengujian, dan panduan. |

## Batas pemeriksaan

- Auditor mengenali pola statis terbatas. Parser shell, alur data, kondisi eksekusi, dan konfigurasi GitHub tidak dianalisis secara lengkap. Kasus di luar pola yang didukung tetap belum dapat dipastikan.
- Mode `--deep` memeriksa snapshot file lokal pada akar repo yang diberikan. Auditor tidak membuktikan bahwa snapshot itu sama dengan kode yang benar-benar akan di-checkout atau dijalankan pada suatu run GitHub. JavaScript/Docker action, script pembantu, dependensi remote, dan bentuk dinamis di luar dukungan dicatat atau dijelaskan sebagai batas analisis; tidak dinyatakan aman.
- Temuan memerlukan peninjauan. Tidak adanya temuan bukan jaminan keamanan, dan SHA atau digest yang dipatok tetap perlu ditinjau serta diperbarui.
- Pemeriksaan script dibatasi pada bentuk yang dikenali. Contohnya, CHA007–CHA008 tidak menyelesaikan URL dinamis, alias atau fungsi shell, heredoc, dan sejumlah opsi downloader yang tidak dikenali.
- CHA001 mengenali referensi lokal `./`, referensi repo sendiri `$/`, dan Docker sebagai bentuk di luar pemeriksaan SHA remote. Lockfile GitHub, cakupan workflow yang terdaftar, dan penerapan kebijakannya tidak diverifikasi. Pada repo yang memakai lockfile secara sah, referensi tag masih dapat memicu CHA001; tinjau kebijakan tersebut sebelum menambahkan pengecualian terarah. Asal-usul commit juga belum diverifikasi.
- CHA003 mendeteksi deklarasi `write-all` secara langsung; kebutuhan dan izin token efektif tidak dihitung secara lengkap.
- Kandidat kredensial CHA004 dan CHA010 tidak disalin ke temuan. Kesalahan YAML tidak menampilkan cuplikan konteks file yang mungkin berisi secret.
- Ukuran workflow dibatasi **2 MiB**, kedalaman YAML maksimal **50**, dan referensi alias maksimal **50**. Anchor dan alias didukung dalam batas tersebut; YAML merge key `<<` ditolak. Kunci berulang, termasuk `on`, ditolak.
- Target symlink, file dengan ekstensi tidak didukung, dan folder tanpa YAML menghasilkan status `2`. Saat menelusuri folder, entri symlink serta folder `.git`, `.venv`, `node_modules`, dan `__pycache__` dilewati.

Catatan evaluasi terbatas pada repo nyata tersedia di [uji coba lapangan](docs/FIELD_PILOT.md). Hasil pilot membantu menemukan kesenjangan; hasil itu bukan pengukuran akurasi yang mewakili seluruh ekosistem.

Perubahan versi dicatat pada [CHANGELOG.md](CHANGELOG.md). Lihat juga [panduan kontribusi](CONTRIBUTING.md) dan [kebijakan pelaporan keamanan](SECURITY.md).
