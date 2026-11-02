# Panduan aturan CHA001–CHA020

Auditor ini membaca workflow GitHub Actions sebagai data, lalu mencari 20 pola yang perlu ditinjau. Auditor tidak menjalankan workflow, mengunduh action, membaca isi artifact, atau mencoba kredensial. Pemeriksaannya berupa heuristik statis yang terfokus; cakupannya tidak mencakup semua kerentanan GitHub Actions.

Definisi ID, judul, tingkat risiko, saran perbaikan, dan sumber aturan ada di [registry](../src/registry.py). Contoh YAML ada di [manifest contoh](../fixtures/rules/manifest.json). Setiap aturan mempunyai contoh `bad` dan `good` yang diperiksa melalui pembaca workflow yang sama dengan CLI.

Dalam panduan ini, **contoh baik memperlihatkan alternatif untuk aturan yang sedang dibahas**. Pengujian juga memastikan seluruh contoh baik tidak menghasilkan temuan ketika semua 20 aturan aktif. Hasil ini tetap terbatas pada heuristik dan snapshot yang tersedia. Semua contoh berada di luar `.github/workflows` dan tidak dijalankan oleh pengujian. Kandidat password/token dalam contoh menggunakan penanda `DEMO_ONLY_NOT_A_REAL_SECRET`; nilainya tidak disalin ke laporan temuan CHA004/CHA010. Domain pada contoh unduhan CHA007 dan digest image pada CHA009/CHA010 bersifat ilustratif; pilih sumber dan digest nyata yang telah ditinjau sebelum digunakan.

## Membaca temuan dan batas pemeriksaan

`severity` adalah tingkat risiko bawaan aturan: `low`, `medium`, `high`, atau `critical`. `confidence` menunjukkan keyakinan pemeriksa terhadap pola yang dikenali. Keduanya adalah kategori yang ditetapkan implementasi, bukan skor CVSS, hasil eksploitasi, atau pengukuran dampak pada repository Anda. Sebuah temuan dengan `confidence: medium` tetap dapat membutuhkan tindakan segera setelah konteksnya dikonfirmasi.

| Aturan | Severity bawaan | Confidence yang digunakan |
| --- | --- | --- |
| CHA001 | medium | high |
| CHA002 | high | high |
| CHA003 | medium | high |
| CHA004 | high | medium |
| CHA005 | medium | medium |
| CHA006 | high | high |
| CHA007 | high | high |
| CHA008 | high | high |
| CHA009 | medium | high |
| CHA010 | high | medium |
| CHA011 | high | medium |
| CHA012 | critical | medium |
| CHA013 | critical | medium |
| CHA014 | high | medium |
| CHA015 | high | medium |
| CHA016 | high | medium |
| CHA017 | high | medium |
| CHA018 | high | high |
| CHA019 | high | high |
| CHA020 | high | medium untuk rentang versi; high untuk SHA berbahaya yang tercatat |

Pengenalan perintah shell berfokus pada bentuk literal Bash/sh. CHA007–CHA008 memilih shell POSIX dan mengikuti beberapa opsi `curl`/`wget` yang dikenali. Pemeriksa tidak menyediakan parser lengkap untuk Bash, PowerShell, cmd, Python, atau JavaScript. Heredoc, kutipan yang tidak lengkap, opsi yang tidak dikenali, perintah yang dibentuk secara dinamis, serta alur data yang rumit dapat dilewati atau berada di luar analisis. Pemeriksaan ekspresi YAML tertentu, misalnya CHA002, dapat tetap berlaku terlepas dari shell.

Nama trigger saja tidak membuktikan adanya kerentanan. `pull_request_target`, `workflow_run`, dan `issue_comment` juga digunakan oleh otomasi yang sah. Aturan tentang batas kepercayaan mencari gabungan trigger, sumber kode/data, lokasi file, dan penggunaan berikutnya yang dikenali. Auditor tidak membaca pengaturan persetujuan, akses runner, perlindungan branch, atau izin organisasi melalui API. Tidak ada temuan berarti tidak ada pola yang cocok pada cakupan pemeriksaan ini; kondisi yang belum dapat ditentukan tetap perlu ditinjau.

## Menentukan kebijakan pemeriksaan

Lihat aturan yang tersedia:

```bash
python3 -m src.auditor --list-rules
```

Secara bawaan, pemindaian yang selesai mengembalikan status `0` walaupun menemukan peringatan. Gunakan kedua opsi berikut untuk menggagalkan CI apabila ada temuan `high` atau `critical`:

```bash
python3 -m src.auditor .github/workflows --fail-on-findings --fail-on-severity high
```

`--fail-on-severity` hanya memengaruhi status keluar ketika dipakai bersama `--fail-on-findings`. Temuan di bawah ambang tetap ditampilkan. Ambang bawaan adalah `low`; status `1` berarti ada temuan yang mencapai ambang, sedangkan status `2` berarti terjadi kesalahan input atau pemindaian.

Pengecualian dapat ditulis sebagai daftar ID atau opsi berulang:

```bash
python3 -m src.auditor .github/workflows --ignore CHA001,CHA005 --format json
```

`--ignore` mengeluarkan aturan tersebut dari pemeriksaan dan laporan temuan. Opsi ini adalah keputusan kebijakan peninjauan, bukan perbaikan pada workflow. Catat alasan, penanggung jawab, dan waktu peninjauan ulang di tempat tim Anda menyimpan keputusan keamanan. Laporan JSON menyertakan `rules_enabled` dan `rules_ignored` agar cakupan pemindaian terlihat.

## CHA001 — Referensi action belum memakai SHA commit lengkap

**Yang diperiksa dan alasannya.** Referensi remote pada `steps[].uses` dan pemanggilan reusable workflow sebaiknya menunjuk ke commit yang telah ditinjau. Tag seperti `@v4` atau branch seperti `@main` dapat berpindah ke kode lain.

**Batas deteksi.** Pemeriksa menerima bentuk 40 karakter heksadesimal sebagai SHA lengkap. Auditor tidak membuktikan bahwa commit itu ada, berasal dari maintainer yang benar, atau bebas kerentanan. Action lokal dengan awalan `./` dilewati; image `docker://` diperiksa oleh CHA009.

**Alternatif yang lebih aman.** Gunakan SHA lengkap dari commit yang telah ditinjau dan siapkan proses pembaruan. SHA yang diketahui berbahaya masih dapat memicu CHA020.

Contoh: [bermasalah](../fixtures/rules/CHA001-bad.yml) · [baik untuk aturan ini](../fixtures/rules/CHA001-good.yml). Referensi: [GitHub — secure use](https://docs.github.com/en/actions/reference/security/secure-use).

## CHA002 — Data tidak tepercaya menjadi bagian kode yang dijalankan

**Yang diperiksa dan alasannya.** Ekspresi seperti `${{ github.event.pull_request.title }}` di dalam `run` diganti sebelum shell berjalan. Isi judul dapat mengubah kode perintah, termasuk ketika ekspresi terlihat berada di dalam tanda kutip shell. Pemeriksa juga memeriksa `with.script` pada `actions/github-script`.

**Batas deteksi.** Sumber yang dikenali meliputi judul/isi PR, beberapa nama branch PR, isi issue/komentar/review/diskusi, dan pesan head commit. Ini bukan penelusuran seluruh input pengguna, seluruh bahasa pemrograman, atau seluruh action yang menerima script.

**Alternatif yang lebih aman.** Kirim nilai melalui `env` atau argumen action, lalu perlakukan sebagai data. Dalam shell, gunakan ekspansi variabel yang dikutip. Periksa kembali jika nilai itu ditulis ke environment file atau PATH; CHA016–CHA017 membahas penggunaan tersebut.

Contoh: [bermasalah](../fixtures/rules/CHA002-bad.yml) · [baik untuk aturan ini](../fixtures/rules/CHA002-good.yml). Referensi: [CodeQL — code injection](https://codeql.github.com/codeql-query-help/actions/actions-code-injection-critical/).

## CHA003 — Izin token `write-all`

**Yang diperiksa dan alasannya.** `permissions: write-all` memberi akses tulis luas kepada token workflow. Dampak kesalahan atau kode berbahaya menjadi lebih besar daripada jika token hanya mempunyai izin yang dibutuhkan.

**Batas deteksi.** Aturan ini hanya mencari nilai `write-all` yang eksplisit pada tingkat workflow atau job. Tidak ada temuan tidak membuktikan bahwa pemetaan izin per item, izin bawaan repository, atau izin token lain sudah minimal.

**Alternatif yang lebih aman.** Tulis izin satu per satu, misalnya `contents: read`, lalu tambahkan izin lain hanya pada job yang memerlukannya.

Contoh: [bermasalah](../fixtures/rules/CHA003-bad.yml) · [baik untuk aturan ini](../fixtures/rules/CHA003-good.yml). Referensi: [GitHub — permissions](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#permissions).

## CHA004 — Kandidat kredensial ditulis langsung di `env`

**Yang diperiksa dan alasannya.** Nama variabel seperti `PASSWORD`, `DEPLOY_TOKEN`, atau `API_KEY` dengan nilai literal dapat menunjukkan kredensial yang tersimpan dalam repository.

**Batas deteksi.** Pemeriksa memakai pola nama dan bentuk nilai, bukan pengujian apakah token benar-benar aktif. Nilai demonstrasi juga dapat memicu aturan. Nilai kosong, referensi ekspresi/variabel yang dikenali, dan nama deskriptif seperti `PRIVATE_KEY_FILE` dilewati. Pemeriksaan ini tidak mencari seluruh jenis secret dalam semua file. Laporan menyebut lokasi dan nama variabel, bukan nilai kandidatnya.

**Alternatif yang lebih aman.** Gunakan GitHub Secrets atau penyedia kredensial yang sesuai. Jika nilai nyata pernah terpapar, pindahkan penyimpanannya dan rotasi kredensial tersebut.

Contoh: [bermasalah](../fixtures/rules/CHA004-bad.yml) · [baik untuk aturan ini](../fixtures/rules/CHA004-good.yml). Referensi: [GitHub — sensitive information](https://docs.github.com/en/actions/reference/security/secure-use#use-secrets-for-sensitive-information).

## CHA005 — Reusable workflow menerima `secrets: inherit`

**Yang diperiksa dan alasannya.** Pemanggilan reusable workflow dengan `secrets: inherit` meneruskan akses secret secara luas. Workflow yang dipanggil bisa mendapatkan lebih banyak secret daripada yang dibutuhkannya.

**Batas deteksi.** Aturan berlaku pada job pemanggil yang mempunyai `uses` dan `secrets: inherit`, termasuk pemanggilan lokal. Auditor tidak membuka workflow tujuan atau menentukan apakah seluruh secret tersebut memang dibutuhkan. Temuan meminta peninjauan cakupan akses.

**Alternatif yang lebih aman.** Tinjau workflow tujuan dan gunakan pemetaan nama secret yang diperlukan saja.

Contoh: [bermasalah](../fixtures/rules/CHA005-bad.yml) · [baik untuk aturan ini](../fixtures/rules/CHA005-good.yml). Referensi: [zizmor — secrets-inherit](https://docs.zizmor.sh/audits/#secrets-inherit).

## CHA006 — Seluruh konteks `secrets` diserialisasikan

**Yang diperiksa dan alasannya.** Ekspresi `${{ toJSON(secrets) }}` menyalin seluruh kumpulan secret menjadi satu nilai. Penggunaannya dapat memperluas paparan ke proses, action, atau log yang menerima nilai tersebut.

**Batas deteksi.** Pemeriksa mencari pemanggilan fungsi tersebut dalam ekspresi YAML pada tingkat workflow, job, dan step. Teks biasa yang sekadar menyebut `toJSON(secrets)`, string literal di dalam ekspresi, atau akses satu secret tidak dianggap cocok. Auditor tidak mengikuti semua kemungkinan cara menggabungkan secret dan tidak membuktikan bahwa nilainya sudah bocor.

**Alternatif yang lebih aman.** Teruskan satu per satu secret yang diperlukan kepada langkah yang membutuhkannya.

Contoh: [bermasalah](../fixtures/rules/CHA006-bad.yml) · [baik untuk aturan ini](../fixtures/rules/CHA006-good.yml). Referensi: [CodeQL — excessive secrets exposure](https://codeql.github.com/codeql-query-help/actions/actions-excessive-secrets-exposure/).

## CHA007 — Respons unduhan langsung dijalankan sebagai script

**Yang diperiksa dan alasannya.** Bentuk seperti `curl https://... | bash` atau `wget -qO- https://... | sh` menjalankan respons jaringan tanpa pemeriksaan integritas terlebih dahulu.

**Batas deteksi.** Pemeriksa mengenali beberapa bentuk literal `curl`/`wget` yang mengirim respons ke keluaran standar dan langsung menyalurkannya ke `bash`/`sh`. Komentar, contoh yang dikutip sebagai teks, unduhan ke file, dan pipe data ke program seperti `jq` tidak disamakan dengan pola tersebut. URL dinamis, heredoc, opsi yang tidak dikenali, dan pola eksekusi lain dapat tidak terdeteksi. Isi server tidak diambil.

**Alternatif yang lebih aman.** Unduh ke file dan periksa asal serta integritasnya sebelum menjalankan, atau gunakan action dengan commit yang telah ditinjau. Contoh baik hanya membaca ukuran file hasil unduhan.

Contoh: [bermasalah](../fixtures/rules/CHA007-bad.yml) · [baik untuk aturan ini](../fixtures/rules/CHA007-good.yml). Referensi: [CWE-494 — download without integrity check](https://cwe.mitre.org/data/definitions/494.html).

## CHA008 — Verifikasi sertifikat HTTPS dimatikan

**Yang diperiksa dan alasannya.** Opsi `curl -k` atau `--insecure` pada transfer HTTPS mematikan pemeriksaan sertifikat server. Identitas endpoint menjadi lebih sulit dipastikan.

**Batas deteksi.** Aturan mencari transfer HTTPS literal `curl` dengan keadaan opsi yang dikenali. Misalnya, `--no-insecure` setelah `-k` mengaktifkan kembali verifikasi. Teks opsi dalam komentar/argumen lain tidak dianggap sebagai opsi aktif. Pemeriksaan ini tidak mencakup semua klien HTTP, semua opsi TLS, atau endpoint yang dibentuk secara dinamis.

**Alternatif yang lebih aman.** Biarkan verifikasi aktif. Jika memakai CA internal, konfigurasi sertifikat CA yang sesuai, misalnya dengan `--cacert`.

Contoh: [bermasalah](../fixtures/rules/CHA008-bad.yml) · [baik untuk aturan ini](../fixtures/rules/CHA008-good.yml). Referensi: [curl — SSL certificates](https://curl.se/docs/sslcerts.html).

## CHA009 — Image container belum dipatok ke digest lengkap

**Yang diperiksa dan alasannya.** Tag image seperti `alpine:3.20` dapat berubah. Pemeriksa mencakup container job, service container, dan step `uses: docker://...`.

**Batas deteksi.** Bentuk yang diterima berakhir dengan `@sha256:` dan 64 karakter heksadesimal. Auditor tidak menghubungi registry untuk memverifikasi image, digest, signature, atau isi image. Referensi dinamis yang tidak dapat ditentukan dilewati. Digest dalam contoh baik hanya menunjukkan format.

**Alternatif yang lebih aman.** Gunakan digest nyata dari image yang telah ditinjau, lalu perbarui melalui proses yang terkendali.

Contoh: [bermasalah](../fixtures/rules/CHA009-bad.yml) · [baik untuk aturan ini](../fixtures/rules/CHA009-good.yml). Referensi: [Docker — image pull by digest](https://docs.docker.com/reference/cli/docker/image/pull/).

## CHA010 — Password registry ditulis langsung dalam workflow

**Yang diperiksa dan alasannya.** Nilai literal pada `container.credentials.password` atau kredensial service container dapat menyimpan password registry di repository.

**Batas deteksi.** Pemeriksa menilai field password yang dikenali, bukan seluruh metode login registry. Username literal saja tidak memicu aturan. Referensi secret/variabel yang dikenali dan password kosong dilewati. Nilai kandidat password tidak disalin ke pesan temuan.

**Alternatif yang lebih aman.** Gunakan referensi secret atau kredensial berumur pendek. Rotasi password nyata yang pernah terpapar.

Contoh: [bermasalah](../fixtures/rules/CHA010-bad.yml) · [baik untuk aturan ini](../fixtures/rules/CHA010-good.yml). Referensi: [GitHub — container credentials](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#jobsjob_idcontainercredentials).

## CHA011 — Job PR dapat memakai runner self-hosted

**Yang diperiksa dan alasannya.** Gabungan trigger `pull_request`/`pull_request_target` dengan label `self-hosted` meminta peninjauan apakah kontribusi yang tidak tepercaya dapat mengakses mesin tersebut.

**Batas deteksi.** Auditor membaca trigger, label runner, serta beberapa kondisi `if` sederhana. Ia tidak membaca pengaturan persetujuan fork, pembatasan runner group, atau tingkat isolasi mesin. Temuan ini tidak membuktikan bahwa kode penyerang sudah berjalan; label atau runner yang dipilih secara dinamis juga dapat berada di luar deteksi.

**Alternatif yang lebih aman.** Gunakan runner yang terisolasi untuk kontribusi tidak tepercaya. Jika tetap memakai self-hosted, tinjau akses, persetujuan, siklus hidup runner, dan keterjangkauan sistem lain.

Contoh: [bermasalah](../fixtures/rules/CHA011-bad.yml) · [baik untuk aturan ini](../fixtures/rules/CHA011-good.yml). Referensi: [GitHub — self-hosted runner hardening](https://docs.github.com/en/actions/reference/security/secure-use#hardening-for-self-hosted-runners).

## CHA012 — Kode PR dijalankan dalam konteks `pull_request_target`

**Yang diperiksa dan alasannya.** Aturan mencari checkout head/fork PR pada `pull_request_target` yang diikuti eksekusi kode dari lokasi checkout tersebut. Menjalankan kode kontribusi dalam konteks yang mempunyai kepercayaan lebih tinggi dapat melintasi batas keamanan.

**Batas deteksi.** Pemeriksa mengenali `actions/checkout`, beberapa input `ref`/`repository` dari konteks PR, lokasi checkout, dan sejumlah bentuk eksekusi seperti script atau perintah build. Ia mengikuti urutan langkah; checkout tepercaya yang membersihkan lokasi dapat memutus hubungan dengan sumber sebelumnya. Trigger saja atau checkout tanpa eksekusi berikutnya tidak cukup untuk temuan ini.

Perlindungan default checkout **v7 yang dikenali**, termasuk satu SHA v7 yang tercatat dalam implementasi, diperhitungkan. Checkout tersebut tidak dianggap mengeksekusi PR yang tidak aman ketika opsi perlindungannya tetap aktif. `allow-unsafe-pr-checkout: true` membuka kembali kasus berisiko; nilai dinamis perlu ditinjau. SHA lain tidak otomatis dipetakan ke versi v7 karena auditor bekerja secara offline.

**Alternatif yang lebih aman.** Jalankan kode kontribusi pada konteks berizin rendah. Dalam otomasi berprivilege, gunakan revisi tepercaya yang telah ditinjau dan hindari eksekusi kode PR.

Contoh: [bermasalah](../fixtures/rules/CHA012-bad.yml) · [baik untuk aturan ini](../fixtures/rules/CHA012-good.yml). Referensi: [GitHub — securely using pull_request_target](https://docs.github.com/en/actions/reference/security/securely-using-pull_request_target).

## CHA013 — Artifact dari run lain mencapai lokasi kode yang dijalankan

**Yang diperiksa dan alasannya.** Pada `workflow_run`, artifact dari run pemicu dapat berisi data atau file yang dikendalikan kontribusi sebelumnya. Risiko muncul apabila hasil unduhan masuk ke lokasi yang kemudian dipakai menjalankan kode.

**Batas deteksi.** Pemeriksa mengikuti penggunaan tertentu `actions/download-artifact` dengan `run-id` pemicu, atau `dawidd6/action-download-artifact`, lalu membandingkan lokasi unduhan dengan eksekusi berikutnya yang dikenali. Ia tidak membaca isi artifact atau memverifikasi siapa pembuatnya. Pembersihan melalui checkout berikutnya diperhitungkan; action unduhan lain dan path dinamis dapat berada di luar cakupan.

**Alternatif yang lebih aman.** Periksa asal run dan artifact. Unduh data tidak tepercaya ke lokasi terpisah, misalnya direktori sementara, dan baca sebagai data tanpa menjalankan script, action lokal, atau proses build dari sana.

Contoh: [bermasalah](../fixtures/rules/CHA013-bad.yml) · [baik untuk aturan ini](../fixtures/rules/CHA013-good.yml). Referensi: [CodeQL — artifact poisoning](https://codeql.github.com/codeql-query-help/actions/actions-artifact-poisoning-critical/).

## CHA014 — Upload artifact dapat menyertakan file sensitif

**Yang diperiksa dan alasannya.** Path upload seperti `.env`, `.npmrc`, private key, atau direktori kredensial dapat memublikasikan informasi yang tidak dimaksudkan untuk penerima artifact.

**Batas deteksi.** Aturan memeriksa input `path` pada `actions/upload-artifact` dan sejumlah nama/glob file sensitif. Pengaturan **`include-hidden-files`**, perubahan perilaku versi yang dikenali, dan pola pengecualian `!path` diperhitungkan. Karena itu, upload luas dengan hidden files dikecualikan tidak otomatis disamakan dengan upload seluruh file tersembunyi. SHA yang belum dikenal tidak selalu dapat dipetakan ke perilaku versi tertentu. Auditor tidak memeriksa file yang benar-benar ada atau memastikan seluruh pola glob memiliki makna lengkap yang sama dengan action.

**Alternatif yang lebih aman.** Upload daftar file keluaran yang jelas, misalnya satu report di `dist/`. Hindari kredensial dalam direktori keluaran dan gunakan pengecualian yang ditinjau bila diperlukan.

Contoh: [bermasalah](../fixtures/rules/CHA014-bad.yml) · [baik untuk aturan ini](../fixtures/rules/CHA014-good.yml). Referensi: [CodeQL — secrets in artifacts](https://codeql.github.com/codeql-query-help/actions/actions-secrets-in-artifacts/).

## CHA015 — Kode/data tidak tepercaya dapat menulis cache berprivilege

**Yang diperiksa dan alasannya.** Cache yang dapat ditulis setelah kode atau data tidak tepercaya memengaruhi isinya dapat membawa perubahan ke workflow berikutnya yang lebih dipercaya.

**Batas deteksi.** Perilaku cache saat ini membatasi akses tulis pada trigger tertentu. Aturan ini memerlukan **`cache-mode: write` atau `write-only` yang eksplisit** pada workflow/job untuk trigger `pull_request_target`, `workflow_run`, atau `issue_comment`. Selain itu, harus ada `actions/cache`/`actions/cache/save` dengan path yang dikenali serta sumber berisiko yang dikenali: eksekusi checkout tidak tepercaya, artifact yang tumpang tindih dengan path cache, atau injeksi langsung pada script terkait. Pemakaian cache biasa atau trigger `pull_request` saja tidak dianggap meracuni cache branch berprivilege.

**Alternatif yang lebih aman.** Pertahankan akses baca saja untuk pekerjaan dengan input berkepercayaan rendah, gunakan restore-only bila cukup, dan pisahkan penulis cache menurut batas kepercayaannya. Nama cache yang berbeda saja belum membuktikan isolasi yang benar.

Contoh: [bermasalah](../fixtures/rules/CHA015-bad.yml) · [baik untuk aturan ini](../fixtures/rules/CHA015-good.yml). Referensi: [GitHub — dependency caching](https://docs.github.com/en/actions/reference/workflows-and-actions/dependency-caching).

## CHA016 — Data tidak tepercaya ditulis ke environment/output file

**Yang diperiksa dan alasannya.** Menulis judul issue atau nilai sejenis langsung ke `$GITHUB_ENV`/`$GITHUB_OUTPUT` memungkinkan baris baru membentuk entri tambahan. Mengutip variabel shell tidak menghapus karakter baris baru.

**Batas deteksi.** Pemeriksa mengikuti beberapa sumber ekspresi tidak tepercaya, variabel `env`, assignment sederhana, serta pembacaan artifact yang dikenali menuju file tersebut. Beberapa bentuk validasi angka, penghapusan CR/LF, encoding satu baris, atau pembatas multiline acak dapat dikenali. Ini bukan analisis alur data dan kontrol shell yang lengkap; pembentukan nama target atau transformasi yang rumit dapat terlewat.

**Alternatif yang lebih aman.** Untuk nilai satu baris, validasi bentuknya atau hapus carriage return/newline sebelum menulis. Untuk data multiline yang memang dibutuhkan, gunakan format multiline dengan pembatas yang sukar bertabrakan dengan isi data. Pilih metode sesuai makna nilai yang ingin disimpan.

Contoh: [bermasalah](../fixtures/rules/CHA016-bad.yml) · [baik untuk aturan ini](../fixtures/rules/CHA016-good.yml). Referensi: [CodeQL — environment-file injection](https://codeql.github.com/codeql-query-help/actions/actions-envvar-injection-critical/).

## CHA017 — Direktori tidak tepercaya ditambahkan ke pencarian program

**Yang diperiksa dan alasannya.** Menulis direktori dari input pengguna ke `$GITHUB_PATH` dapat membuat langkah berikutnya menemukan program milik penyerang lebih dahulu.

**Batas deteksi.** Aturan mengikuti beberapa sumber dan assignment yang sama dengan CHA016 menuju `$GITHUB_PATH`. Ia mengenali sebagian pemeriksaan allowlist path yang eksplisit. Aturan belum mencakup semua cara mengubah `PATH`, pemilihan executable secara dinamis, atau izin tulis pada direktori yang ditambahkan. Menghapus newline saja tidak membuat sebuah path dapat dipercaya.

**Alternatif yang lebih aman.** Tambahkan hanya direktori yang dipilih dan dikendalikan administrator. Jika menerima pilihan pengguna, cocokkan secara persis dengan daftar path yang disetujui dan periksa bahwa pengguna tidak dapat mengganti isi direktori tersebut.

Contoh: [bermasalah](../fixtures/rules/CHA017-bad.yml) · [baik untuk aturan ini](../fixtures/rules/CHA017-good.yml). Referensi: [CodeQL — executable path injection](https://codeql.github.com/codeql-query-help/actions/actions-envpath-injection-critical/).

## CHA018 — Penulisan `if` membentuk string yang dianggap benar

**Yang diperiksa dan alasannya.** `if: ${{ github.actor }} == 'alice'` menyisakan teks pembanding di luar ekspresi. Gabungan hasil ekspresi dan teks tersebut menjadi string tidak kosong yang dianggap benar, sehingga pembatasan yang dimaksud tidak bekerja.

**Batas deteksi.** Pemeriksa hanya membaca field `if` pada job/step. Ia mencari teks literal di luar blok ekspresi, **termasuk spasi dan newline yang dipertahankan oleh YAML**, serta beberapa gabungan blok yang memiliki keluaran literal pasti tidak kosong. Gabungan yang seluruh hasilnya belum diketahui tidak otomatis dianggap selalu benar. Kondisi sah seperti `always()`, `${{ always() }}`, atau ekspresi tanpa pembungkus `${{ }}` tidak ditandai hanya karena bentuk tersebut. Pemeriksa bukan validator lengkap seluruh bahasa ekspresi.

**Alternatif yang lebih aman.** Letakkan seluruh perbandingan dalam satu ekspresi tanpa karakter di luarnya: `if: ${{ github.actor == 'alice' }}`. Spasi di dalam pembungkus ekspresi diperbolehkan. Jika memakai `${{ }}` dalam block scalar, `if: |` atau `if: >` menyisakan newline; gunakan `|-`/`>-` untuk membuang newline terakhir, atau tulis kondisi tanpa pembungkus ekspresi. Tinjau juga apakah identitas yang dibandingkan memang sesuai dengan tujuan otorisasi.

Perilaku spasi ini dikonfirmasi dalam [parser runner](https://github.com/actions/runner/blob/110142c2c501c6ae9373d553efa826bedbaab5f7/src/Sdk/DTObjectTemplating/ObjectTemplating/TemplateReader.cs#L563-L619): teks sebelum/sesudah ekspresi dipertahankan saat nilai gabungan diubah menjadi pemanggilan `format()`. Karena itu, whitespace di luar ekspresi bukan sekadar hiasan format.

Contoh: [bermasalah](../fixtures/rules/CHA018-bad.yml) · [baik untuk aturan ini](../fixtures/rules/CHA018-good.yml). Referensi: [CodeQL — always-true if expression](https://codeql.github.com/codeql-query-help/actions/actions-if-expression-always-true-critical/).

## CHA019 — Pengecekan identitas memakai substring

**Yang diperiksa dan alasannya.** `contains('alice,bob', github.actor)` melakukan pencarian substring. Nama yang hanya merupakan bagian dari string tersebut dapat diterima meskipun bukan anggota daftar identitas yang dimaksud.

**Batas deteksi.** Pemeriksa mencari `contains()` dengan argumen pertama berupa string literal dan argumen identitas yang dikenali, seperti `github.actor`, `github.triggering_actor`, atau konteks `user.login`, dalam `if` job/step. Ia tidak menandai semua penggunaan `contains()`: pencarian label, teks biasa, dan membership array memiliki makna berbeda. Daftar yang dibentuk dinamis tidak dapat dipastikan bentuknya oleh aturan ini.

**Alternatif yang lebih aman.** Gunakan persamaan identitas secara eksplisit atau `contains(fromJSON('["alice","bob"]'), github.actor)` agar yang dibandingkan adalah elemen array lengkap.

Contoh: [bermasalah](../fixtures/rules/CHA019-bad.yml) · [baik untuk aturan ini](../fixtures/rules/CHA019-good.yml). Referensi: [zizmor — unsound-contains](https://docs.zizmor.sh/audits/#unsound-contains).

## CHA020 — Referensi action cocok dengan snapshot advisory

**Yang diperiksa dan alasannya.** Action yang dipatok sekalipun dapat menunjuk ke rilis rentan atau commit berbahaya. Aturan ini mencocokkan referensi action dengan [snapshot lokal](../src/data/advisories.json), lalu menyertakan ID dan tautan advisory dalam temuan.

**Batas deteksi.** Snapshot bawaan hanya berisi **tiga entri**, diverifikasi terhadap sumber GitHub pada **2026-11-02**. Ini bukan database lengkap, tidak diperbarui otomatis, dan tidak menjanjikan cakupan advisory terbaru. Pencocokan hanya menerima versi stabil persis `X.Y.Z` dengan awalan `v` opsional, atau SHA lengkap yang secara eksplisit tercatat sebagai berbahaya. Tag berpindah seperti `@v4`, branch, prerelease/build metadata, dan SHA lain yang belum dikenal dilewati karena tidak dapat ditentukan secara offline. Hasil kosong pada referensi tersebut tidak membuktikan action aman.

| Action dan sumber advisory | Rentang yang dicatat | Versi perbaikan yang dipublikasikan |
| --- | --- | --- |
| [tj-actions/changed-files — GHSA-mrrh-fwg8-r2c3](https://github.com/advisories/GHSA-mrrh-fwg8-r2c3) | `<=45.0.7` | `46.0.1` |
| [actions/download-artifact — GHSA-cxww-7g56-2vh6](https://github.com/actions/download-artifact/security/advisories/GHSA-cxww-7g56-2vh6) | `>=4.0.0,<4.1.3` | `4.1.3` |
| [dawidd6/action-download-artifact — GHSA-5xr6-xhww-33m4](https://github.com/dawidd6/action-download-artifact/security/advisories/GHSA-5xr6-xhww-33m4) | sumber: `<v6`; perbandingan versi stabil: `<6.0.0` | `v6` |

Advisory changed-files membahas insiden **14–15 Maret 2025** dan menyatakan bahwa tag yang terpengaruh kemudian dipulihkan. Karena itu, kecocokan rentang versi tidak membuktikan bahwa tag saat ini masih menunjuk ke kode berbahaya. Snapshot juga menyimpan SHA berbahaya `0e58ed8671d6b60d0890c21b07f8835ace038e67`; kecocokan SHA tersebut diberi `confidence: high`, sedangkan kecocokan rentang diberi `medium`. Periksa riwayat run, commit yang benar-benar digunakan, serta kondisi khusus dalam advisory.

**Alternatif yang lebih aman.** Baca advisory yang ditautkan, pilih rilis/commit perbaikan yang telah ditinjau, dan perbarui data advisory secara berkala. Informasi versi perbaikan bukan pembuktian bahwa seluruh konfigurasi dan dependensi action sudah aman.

Contoh: [bermasalah](../fixtures/rules/CHA020-bad.yml) · [baik untuk aturan ini](../fixtures/rules/CHA020-good.yml). Contoh baik memakai SHA commit yang dipetakan oleh tag resmi `v4.1.3`, dengan [hasil pemetaan yang diperiksa melalui GitHub API](https://api.github.com/repos/actions/download-artifact/git/ref/tags/v4.1.3) dicatat dalam manifest. Auditor sendiri tidak menyimpulkan nomor versi dari SHA itu. Pengujian unit CHA020 juga memeriksa batas versi `v4.1.2` dan `v4.1.3` secara langsung. Referensi aturan: [CodeQL — vulnerable action](https://codeql.github.com/codeql-query-help/actions/actions-vulnerable-action/).

### Memakai snapshot advisory sendiri

Salin format [snapshot bawaan](../src/data/advisories.json), periksa sumber aslinya, lalu berikan file JSON lokal:

```bash
python3 -m src.auditor .github/workflows --advisory-file data/advisories.local.json --format json
```

File ini **menggantikan** snapshot bawaan untuk pemindaian tersebut. Tidak ada penggabungan otomatis atau pengambilan data jaringan. Mengganti file tanpa membawa tiga entri bawaan juga berarti entri itu tidak diperiksa lagi, kecuali Anda memasukkannya dalam file pengganti.

Schema yang diterima adalah versi `1` dengan field tingkat atas berikut:

| Field | Isi |
| --- | --- |
| `schema_version` | Bilangan bulat `1`. |
| `checked_at` | Tanggal verifikasi sumber, format `YYYY-MM-DD`. |
| `coverage` | Keterangan jujur mengenai cakupan dan keterbatasan snapshot. |
| `advisories` | Array entri advisory; boleh kosong jika memang itu kebijakan data yang dipilih. |

Setiap entri harus mempunyai field di bawah ini. `notes` adalah satu-satunya field opsional.

| Field entri | Isi |
| --- | --- |
| `id` | ID GHSA, misalnya `GHSA-cxww-7g56-2vh6`. |
| `action` | Nama action yang dicocokkan persis, misalnya `actions/download-artifact`; kapitalisasi nama tidak memengaruhi pencocokan. |
| `summary` | Ringkasan singkat dalam teks biasa tanpa karakter kontrol. |
| `source` | URL advisory GitHub dengan ID GHSA yang sama, pada `/advisories/…` atau `/owner/repo/security/advisories/…`. |
| `affected_ranges` | Array rentang versi stabil lengkap. Contoh: `[">=4.0.0,<4.1.3"]`. |
| `patched_versions` | Array versi perbaikan sesuai publikasi, misalnya `["4.1.3"]` atau `["v6"]`; bersifat informasi. |
| `malicious_shas` | Array SHA berbahaya yang telah diverifikasi, masing-masing 40 karakter heksadesimal; boleh kosong. |
| `notes` | Opsional: syarat konfigurasi, konteks insiden, mitigasi, atau alasan normalisasi rentang. |

Di dalam satu rentang, perbandingan yang dipisahkan koma harus semuanya terpenuhi. Antarelemen `affected_ranges`, cukup satu rentang yang cocok. Operator yang diterima adalah `=`, `<`, `<=`, `>`, dan `>=`; operator yang tidak ditulis berarti persamaan. Bentuk seperti `^4`, `~4.1`, `*`, `||`, atau kode Python tidak diterima. Sedikitnya salah satu dari `affected_ranges` dan `malicious_shas` harus berisi data.

Validator memeriksa struktur, format, tanggal, rentang, dan bentuk tautan. Ia tidak membuktikan kebenaran isi advisory pengganti. File yang tidak valid menghasilkan kesalahan pemindaian/status `2` dengan pesan umum, tanpa menyalin isi file ke pesan kesalahan. Periksa perubahan snapshot dan simpan asal datanya agar keputusan peninjauan dapat ditelusuri.
