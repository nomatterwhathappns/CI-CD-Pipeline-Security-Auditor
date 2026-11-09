# Analisis alur data dan file lokal

Versi 1.2.0 memperluas cara auditor membaca GitHub Actions. CHA023 menelusuri beberapa perpindahan data di dalam workflow secara bawaan. Opsi `--deep` kemudian mengikuti composite action dan reusable workflow lokal yang dipanggil, sehingga pemeriksaan tidak berhenti pada file workflow awal.

Pemeriksaan tetap berbasis kode dan aturan yang dapat diuji. Tidak ada model AI, eksekusi workflow, checkout Git, pengambilan action remote, atau percobaan kredensial saat pemindaian. Penambahan ini belum membuktikan kesetaraan cakupan atau ketepatan dengan peninjauan AI.

## Mulai dari akar repo yang diperiksa

CLI `cha-auditor` harus sudah terpasang pada virtual environment. Dari folder utama proyek yang ingin diperiksa:

```bash
cha-auditor .github/workflows --deep --repo-root . --format json
```

Untuk proyek di lokasi lain:

```bash
cha-auditor /lokasi/proyek/.github/workflows \
  --deep --repo-root /lokasi/proyek --format json
```

`--repo-root` menetapkan batas pembacaan file lokal, bukan lokasi pemasangan auditor. Target awal dan referensi lokal harus berada di dalam batas tersebut. Gunakan snapshot repo yang ingin ditinjau; auditor tidak memeriksa apakah snapshot itu sama dengan kode yang akhirnya dijalankan pada suatu run GitHub.

Tanpa `--deep`, bentuk CLI lama tetap memeriksa file workflow yang dipilih. CHA023 tetap aktif untuk bentuk penelusuran dalam satu workflow yang didukung. Panduan sumber data, bentuk ekspresi, dan batas CHA023 ada di [panduan penelusuran data](DATAFLOW.md).

## Yang diikuti oleh mode deep

Contoh tiga file tersedia pada `fixtures/deep/demo`. Kedua contoh berawal dari judul PR dan meneruskannya melalui reusable workflow ke composite action. Pada contoh bermasalah, nilainya menjadi sumber script; pada contoh baik, nilainya tetap menjadi data melalui environment.

```bash
cha-auditor fixtures/deep/demo/.github/workflows/entry-bad.yml \
  --deep --repo-root fixtures/deep/demo --fail-on-findings
cha-auditor fixtures/deep/demo/.github/workflows/entry-good.yml \
  --deep --repo-root fixtures/deep/demo --fail-on-findings
```

Contoh pertama menghasilkan CHA023 dan status `1`; contoh kedua menghasilkan status `0` pada cakupan aturan saat ini. File berada di bawah `fixtures`, sehingga bukan workflow aktif repo ini. Pemindaian tidak menjalankannya.

Contoh hubungan yang dapat ditelusuri:

```text
.github/workflows/check.yml
  ├─ steps[].uses: ./.github/actions/check-title
  │    └─ action.yml → runs.using: composite → runs.steps
  └─ jobs.<job>.uses: ./.github/workflows/reusable.yml
       └─ jobs → steps
```

Referensi repo sendiri dengan awalan `$/` juga dikenali. Penelusuran action mencari metadata `action.yml` atau `action.yaml` pada direktori action; composite action menyimpan langkahnya pada `runs.steps`. Reusable workflow dipanggil pada tingkat job, dengan file di `.github/workflows` tanpa subfolder. Bentuk dan konteks tersebut mengikuti [metadata action](https://docs.github.com/en/actions/reference/workflows-and-actions/metadata-syntax) serta [referensi reusable workflow](https://docs.github.com/en/actions/how-tos/reuse-automations/reuse-workflows).

File yang berhasil diikuti dibaca sebagai data dan diperiksa menggunakan aturan yang sesuai. Panggilan yang berbeda ke file yang sama dapat memiliki input yang berbeda; konteks pemanggil dipertahankan untuk penelusuran data yang didukung. Temuan tetap menunjuk ke file sumber yang diperiksa, bukan berpura-pura bahwa semua kode berada di workflow pemanggil.

## Input dan konteks pemanggilan

Nilai input yang berasal dari data tak tepercaya dapat ditelusuri menuju `inputs.<nama>` di file tujuan untuk bentuk panggilan yang didukung. Tujuannya menemukan saat nilai tersebut menjadi bagian sumber script, bukan menyatakan bahwa setiap penggunaan input berbahaya.

Ada batas konteks yang perlu dijaga:

- Environment pada tingkat workflow pemanggil tidak otomatis menjadi environment reusable workflow. Perpindahan ke workflow tujuan memakai input/output yang sesuai.
- Composite action menggunakan konteks `inputs`; auditor tidak mengasumsikan adanya variabel otomatis `INPUT_*` untuk composite action.
- Output step dipakai sesuai urutan langkah yang dikenali. Output job melalui `needs` dibatasi pada dependensi langsung yang dideklarasikan.

Rujukan perilaku platform: [batas reusable workflow](https://docs.github.com/en/actions/reference/workflows-and-actions/reusing-workflow-configurations), [input composite action](https://docs.github.com/en/actions/reference/workflows-and-actions/metadata-syntax#inputs), dan [konteks `needs`](https://docs.github.com/en/actions/reference/workflows-and-actions/contexts#needs-context).

Penelusuran ini tidak meniru seluruh evaluasi GitHub. Kondisi bercabang, matrix, sanitasi data, perubahan filesystem saat runtime, dan efek kode dalam action yang tidak dibaca dapat tetap berada di luar analisis. Bukti yang ditampilkan adalah kemungkinan alur statis pada bentuk yang dikenali; konteks nyata tetap perlu ditinjau.

## Membaca cakupan hasil

JSON schema 1.3 menambahkan objek `analysis`. Lihat mode yang dijalankan, daftar file yang dianalisis, hubungan pemanggilan, batas penelusuran, dan `unresolved_references` yang belum dapat diselesaikan.

| Field dalam `analysis` | Isi |
| --- | --- |
| `mode` | `workflow` untuk pemeriksaan file awal atau `deep` untuk penelusuran referensi lokal. |
| `files_analyzed` | Daftar file YAML unik yang berhasil dianalisis. |
| `unresolved_references` | Bentuk ekspresi, penulisan output, referensi, atau batas yang dikenali belum terselesaikan. Daftar ini tidak menginventarisasi seluruh kode yang mungkin berjalan. |
| `edges` | Hubungan file pemanggil dan file tujuan yang diikuti dalam mode deep. |
| `limits`, `contexts_analyzed`, `total_source_bytes` | Batas graf, jumlah konteks yang dianalisis, serta total ukuran sumber yang dibaca pada mode deep. |
| `dataflow_limits` | Batas penelusuran data yang dilaporkan saat analisis tersebut dijalankan. |
| `source_digest` | Digest himpunan sumber pada mode deep, dipakai untuk mengikat baseline ke file pemanggil dan tujuan. |

Pada mode deep, `files_scanned` menghitung file YAML unik yang berhasil dianalisis, termasuk metadata composite action yang dicapai. File yang sama tidak dihitung ulang hanya karena dipanggil beberapa kali. Pemeriksaan konteks pemanggilan dapat terjadi lebih dari sekali untuk file yang sama; jumlah file bukan jumlah seluruh konteks atau seluruh kode yang dijalankan.

Referensi remote, action JavaScript/Docker, referensi dinamis, siklus, dan batas penelusuran dapat membuat cakupan tidak lengkap. Detail yang dikenali dicatat sebagai bagian yang belum dianalisis. Script pembantu yang disebut dalam `run`, misalnya `python tools/build.py`, tidak dibaca oleh mode ini; daftar referensi yang belum terselesaikan bukan inventaris lengkap semua kode yang mungkin berjalan. Tidak ada temuan berarti tidak ada pola yang cocok pada cakupan yang diperiksa; bagian yang belum dianalisis tidak dinyatakan aman.

Jika kebijakan CI mengharuskan semua referensi yang dicatat terselesaikan, gunakan:

```bash
cha-auditor .github/workflows --deep --repo-root . \
  --fail-on-unresolved --fail-on-findings --format json
```

`--fail-on-unresolved` memerlukan `--deep` dan menghasilkan status `2` bila ada referensi yang dicatat belum terselesaikan. Tanpa opsi tersebut, informasi cakupan tetap ditampilkan tetapi tidak sendiri menggagalkan pemeriksaan. Kesalahan input atau pembacaan tetap menghasilkan status `2`; temuan yang mencapai ambang dengan `--fail-on-findings` menghasilkan status `1`.

Sebuah workflow yang memakai action remote dapat menghasilkan bagian yang belum terselesaikan meskipun action dipatok dengan SHA. Pinning menunjukkan pemilihan revisi; mode offline ini tetap tidak membaca implementasi remote tersebut. Kebijakan `--fail-on-unresolved` sengaja lebih ketat dan dapat menggagalkan workflow yang sah sampai cakupannya ditinjau.

## Batas filesystem dan sumber daya

Penelusuran dibatasi pada akar repo, menolak path symlink, dan menggunakan pembaca YAML aman yang sama dengan pemeriksaan biasa. Batas graf saat ini adalah delapan tingkat hubungan lokal, 100 dokumen, 200 konteks pemanggilan, total 8 MiB sumber YAML, serta delapan pengulangan per konteks untuk meneruskan output file tujuan kembali ke pemanggil. Batas per dokumen tetap 2 MiB dengan pembatasan kedalaman YAML dan alias. Analisis data juga mempunyai batas job, langkah, ekspresi, dan panjang bukti; lihat [batas CHA023](DATAFLOW.md). Metadata analisis melaporkan batas yang digunakan. Batas tersebut mengendalikan pemrosesan, bukan menyatakan bahwa bagian setelah batas telah aman.

Referensi yang mencoba keluar dari akar repo tidak dibaca. Siklus atau referensi yang tidak dapat diikuti dilaporkan agar pemeriksaan yang tidak lengkap tidak terlihat sebagai keberhasilan mencakup seluruh repo.

Gunakan folder repo yang berada dalam kendali Anda selama pemindaian. Mode ini membaca snapshot lokal, bukan filesystem yang dikunci terhadap perubahan serentak oleh proses lain. Pemilihan ulang checkout, dependensi yang diunduh oleh script, atau kode yang dihasilkan pada runtime tidak direkonstruksi.

## Baseline dan laporan

Laporan teks, JSON, SARIF, pengecualian terarah, dan baseline tetap tersedia. Bukti alur data dan konteks panggilan menambahkan lokasi/identitas yang ditelusuri; nilai secret dan source script mentah tidak disalin sebagai bukti.

Pada mode deep, identitas baseline juga terikat pada digest himpunan file yang dianalisis. Perubahan isi file pemanggil atau file lokal yang dicapai mengharuskan peninjauan ulang temuan deep, walaupun file yang memuat lokasi temuan belum berubah. Ini bersifat konservatif: perubahan yang tidak berkaitan juga dapat membuat temuan dianggap baru.

Baseline tetap keputusan penerimaan temuan lama, bukan bukti keamanan. Jangan memperbaruinya otomatis untuk membuat CI hijau. Panduan pemakaian baseline dan pengecualian ada di [panduan tim](USAGE.md).

## Evaluasi yang masih diperlukan

Tes pada contoh positif/negatif memeriksa perilaku bentuk yang didukung, termasuk perbedaan konteks pemanggil. Cakupan pada repo nyata yang beragam, masalah yang terlewat, serta peringatan keliru tetap perlu diukur pada sampel independen.

Hasil [pilot versi 1.1.0](FIELD_PILOT.md) adalah catatan versi sebelumnya. Perluasan graf dan alur data tidak secara otomatis mengubah hasil pilot itu menjadi ukuran akurasi versi 1.2.0.

Sebagai pemeriksaan kompatibilitas, 56 blob workflow historis yang sama diverifikasi dan dipindai ulang menggunakan mode bawaan 1.2.0: 56 file berhasil dipindai, tanpa kesalahan, dengan 26 peringatan konfigurasi yang sama (22 CHA001 dan 4 CHA009). [Ringkasan pengulangan](../evaluation/regression-1.2.json) menyimpan hasil tersebut. Pengulangan ini tidak menguji seluruh panggilan lokal repo sumber dan bukan evaluasi independen ketepatan CHA023 atau mode deep.
