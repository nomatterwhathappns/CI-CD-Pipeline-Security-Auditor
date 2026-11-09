# CHA023 — Menelusuri data menuju sumber script

Versi 1.2.0 menambahkan penelusuran data statis yang dibatasi. Tujuannya mengenali sumber teks tidak tepercaya walaupun teks tersebut diteruskan melalui `env`, input, output langkah, atau output job sebelum disisipkan ke sumber script. Pemeriksaan ini aktif pada pemindaian workflow biasa; `--deep` menambahkan penelusuran file lokal dan pengikatan input/output antarfile.

Tidak ada AI atau eksekusi script dalam analisis. Hasilnya merupakan kemungkinan alur pada bentuk yang dikenali, bukan bukti bahwa workflow telah dieksploitasi.

## Contoh yang dicari

```yaml
on: pull_request
jobs:
  check:
    runs-on: ubuntu-latest
    env:
      TITLE: ${{ github.event.pull_request.title }}
    steps:
      - run: echo "${{ env.TITLE }}"
```

CHA023 dapat menunjukkan jalur `event → env TITLE → sumber script`. Ekspresi GitHub diganti sebelum script dijalankan, sehingga tanda kutip shell di sekitar ekspresi belum menjadikan teks tersebut data yang aman. Sebaliknya, `run: printf '%s\n' "$TITLE"` tidak menghasilkan CHA023 hanya karena variabel environment berisi data PR: pada bentuk itu nilai diperlakukan sebagai data, bukan dipakai untuk membentuk sumber script. Lihat [panduan injeksi script GitHub](https://docs.github.com/en/actions/reference/security/secure-use#good-practices-for-mitigating-script-injection-attacks).

Ekspresi event yang langsung disisipkan ke script tetap diperiksa oleh CHA002. Parser ekspresi yang sama membantu CHA002 membedakan akses properti bracket, teks literal, hasil boolean, dan penggunaan argumen `format`. CHA023 membutuhkan setidaknya satu perpindahan melalui env/input/output; ia tidak menduplikasi kasus yang hanya berisi akses event langsung.

## Perpindahan yang dikenali

- Environment tingkat workflow, job, dan langkah, dengan penimpaan pada lingkup yang lebih khusus. Entri dalam satu peta environment dievaluasi terhadap lingkup sebelumnya; auditor tidak mengarang urutan alias antarentri pada peta yang sama.
- Panggilan melalui `with` menuju input composite action atau reusable workflow lokal, bila mode deep dapat membaca file tujuan. Input yang belum memiliki bukti sumber tidak otomatis dianggap berbahaya.
- Beberapa bentuk POSIX `echo "name=$VALUE" >> "$GITHUB_OUTPUT"` dan `printf '%s\n' "name=$VALUE" >> "$GITHUB_OUTPUT"`. Penugasan variabel lokal sederhana dan penulisan ke `GITHUB_ENV` juga dikenali. Nilai dari `GITHUB_ENV` baru diterapkan ke langkah berikutnya.
- Output langkah yang sudah dijalankan sebelumnya; output job yang diekspor dan diakses melalui dependensi `needs` langsung. Urutan deklarasi job dalam YAML tidak dianggap sebagai urutan eksekusi.
- Output reusable workflow dan composite action yang dideklarasikan, bila pengikatan panggilan lokal dapat diselesaikan oleh mode deep.

Variabel shell POSIX dibedakan berdasarkan huruf besar/kecil. Referensi `$TITLE` berbeda dari `$title`. Payload shell dalam tanda kutip tunggal tidak dianggap memperluas `$TITLE`; ekspresi `${{ ... }}` tetap diproses oleh GitHub walaupun muncul di dalam kutipan shell. Penulisan menuju nama file literal `'$GITHUB_OUTPUT'` tidak dianggap sebagai penulisan output GitHub.

Pencarian properti `env` dalam ekspresi juga mengikuti OS runner yang dikenali: Windows memakai pencarian tanpa membedakan kapitalisasi, sedangkan Linux/macOS membedakannya. Jika OS belum dapat ditentukan dan hanya nama berbeda kapitalisasi yang cocok, auditor mencatat `env-case-unknown` tanpa mengarang alur. Nama yang cocok persis tetap dapat ditelusuri. Ini mengikuti [implementasi environment context runner](https://github.com/actions/runner/blob/main/src/Runner.Worker/StepsRunner.cs), dengan inferensi OS statis yang terbatas pada label runner yang dikenali.

Perilaku input/output platform dirujuk dari [output langkah dan job](https://docs.github.com/en/actions/how-tos/write-workflows/choose-what-workflows-do/pass-job-outputs), [metadata composite action](https://docs.github.com/en/actions/reference/workflows-and-actions/metadata-syntax), dan [reusable workflow](https://docs.github.com/en/actions/how-tos/reuse-automations/reuse-workflows).

## Ekspresi dan sumber

Sumber event yang diperiksa mengikuti daftar konteks tidak tepercaya yang didukung proyek, seperti judul/isi PR atau issue, isi komentar/review/diskusi, nama branch PR tertentu, serta pesan head commit. Ini belum mencakup seluruh input pengguna di GitHub.

Parser mengenali akses properti titik/bracket dengan nama literal, beberapa operator boolean/perbandingan, `format` dengan placeholder angka dan escape kurung kurawal, serta bentuk terbatas `toJSON`, `fromJSON`, dan `join`. Hasil perbandingan dan fungsi boolean tidak diperlakukan sebagai teks arbitrer dari penyerang. `format` menelusuri argumen yang benar-benar dirujuk; argumen tambahan yang tidak dipakai tidak otomatis menjadi sumber.

Sumber script yang diperiksa adalah isi `run` dan `with.script` pada `actions/github-script` yang dikenali. Penyisipan tidak langsung ke script mendapat confidence `medium` untuk ditinjau bersama kondisi dan konteks nyata.

## Bukti dan cakupan yang belum terselesaikan

Temuan menyertakan `dataflow_trace`: daftar jenis perpindahan, nama konteks/identifier, file, job, langkah, dan posisi lingkup sumber bila tersedia. Nilai secret, nilai input mentah, dan isi script tidak disalin sebagai bukti. Panggilan lokal yang diikuti juga mempunyai konteks panggilan pada laporan deep.

Bentuk ekspresi yang tidak didukung, environment dinamis, output shell yang tidak dikenali, siklus dependensi job, dan batas analisis yang tercapai dicatat dalam metadata cakupan. Bagian itu tidak dinyatakan aman. Laporan teks merangkum bahwa ada cakupan belum terselesaikan; JSON/SARIF menyimpan detail yang tersedia.

Penulisan output hanya dimodelkan untuk script POSIX linear dengan kutipan yang lengkap pada satu baris. Blok kondisi, loop, fungsi shell, heredoc, kutipan multibaris, pengelompokan/pipe/compound command, substitusi perintah, PowerShell, dan format output multibaris memerlukan analisis lain. Bentuk yang terdeteksi berada di luar model dicatat sebagai belum terselesaikan; auditor tidak menjalankan bentuk itu untuk mengetahui hasilnya.

Kondisi `if: false` dan bentuk false literal yang dikenali dilewati untuk alur CHA023. Kondisi lain, validasi/sanitasi, matrix, proses yang mengubah environment sendiri, serta efek action JavaScript/Docker atau script pembantu belum dianalisis secara lengkap. Tidak adanya temuan tidak membuktikan tidak adanya jalur injeksi.

Pengikatan antarfile membawa bukti sumber yang dikenali melalui argumen panggilan. Evaluasi penuh default input, konversi tipe input, dan nilai literal untuk menyelesaikan semua cabang di file tujuan belum dimodelkan. Daftar cakupan belum terselesaikan juga bukan inventaris lengkap seluruh bentuk yang berada di luar model.

## Batas pemrosesan

Analisis membatasi 100 job, 1000 langkah per job, 1000 baris untuk pemodelan penulisan shell per script, 8192 karakter dan 256 token per ekspresi, serta 32 simpul bukti per alur. Batas aktif tersedia dalam metadata analisis. Jalur yang mencapai batas bukti tetap dapat menghasilkan peringatan, dengan catatan bahwa bukti telah dibatasi.

Mode deep mempunyai batas file, kedalaman, konteks panggilan, dan ukuran total tambahan. Lihat [panduan deep](DEEP_ANALYSIS.md). Batas ini menjaga analisis tetap terbatas; bagian yang terlewat sesudah batas tidak dianggap sudah diperiksa.
