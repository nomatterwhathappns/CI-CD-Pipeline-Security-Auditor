# Uji awal pada workflow publik

Pada 9 November 2026, versi pengembangan 1.1.0 diperiksa memakai 56 workflow dari tujuh repo publik. Tujuannya menemukan masalah kompatibilitas dan pola peringatan yang perlu diperbaiki. Sampel ini dipilih secara praktis, bukan secara acak atau untuk mewakili seluruh GitHub.

Semua file workflow YAML langsung di folder `.github/workflows` dari tujuh listing repo dipilih. File dari subfolder, kode action yang dirujuk, pengaturan repository, dan seluruh riwayat run tidak termasuk. Konten diperlakukan sebagai data; workflow dan script tidak dijalankan. Tidak ada pesan atau issue yang dikirim kepada maintainer repo tersebut.

## Hasil setelah koreksi metadata CHA004

| Repository | File diverifikasi/dipindai | Peringatan | Aturan |
| --- | ---: | ---: | --- |
| pallets/flask | 5 | 0 | — |
| pypa/pip | 6 | 0 | — |
| psf/requests | 8 | 0 | — |
| cli/cli | 15 | 0 | — |
| expressjs/express | 5 | 0 | — |
| docker/buildx | 10 | 1 | CHA001 |
| actions/checkout | 7 | 25 | CHA001, CHA009 |
| **Total** | **56** | **26** | **22 CHA001; 4 CHA009** |

Seluruh 56 file cocok dengan Git blob SHA yang dicatat dan berhasil dipindai tanpa kesalahan pembacaan. Peringatan tersisa menandai pola referensi action/image yang memerlukan peninjauan kebijakan. Angka itu **bukan jumlah kerentanan yang terbukti dapat dieksploitasi**. Repo tanpa peringatan juga belum dinyatakan aman.

## Kekeliruan yang ditemukan dan diperbaiki

Sebelum koreksi, ada 36 peringatan. Sepuluh di antaranya berasal dari metadata pada dua workflow agentic yang dihasilkan di `cli/cli`:

- Enam `GH_AW_SECRET_NAMES` berisi daftar nama environment, bukan nilai secret.
- Dua `GH_AW_TOKEN_USAGE_SUMMARY_TITLE` berisi label `Threat Detection Token Usage`.
- Dua `GH_AW_GITHUB_TOKEN_SOURCE` berisi jenis penyedia `app`.

Isi dan pemakaiannya ditinjau pada dua blob sumber: [dependabot-triage.lock.yml](https://api.github.com/repos/cli/cli/git/blobs/4353c564892e9a2bd9290abb25e0fde83783fb7b) dan [issue-triage.lock.yml](https://api.github.com/repos/cli/cli/git/blobs/a9e505555f720773157a217c20fe34ab61b8c41a). Pencocokan nama sensitif CHA004 sebelumnya terlalu luas untuk metadata tersebut.

Perbaikan dibatasi pada nama field dan bentuk/nilai yang dikenali. `GH_AW_SECRET_NAMES` membutuhkan minimal dua identifier environment huruf besar yang dipisahkan koma tanpa spasi/baris baru. Kedua field lainnya hanya dikecualikan untuk nilai persis di atas. Nama serupa atau nilai yang tidak dikenali tetap menjadi kandidat. Enam pengujian regresi memastikan perbaikan ini dan penyamaran nilai tetap berlaku. Tidak ada pengecualian umum untuk semua akhiran `_SOURCE`, `_TITLE`, atau `_NAMES`.

Pemeriksaan ulang menurunkan peringatan menjadi 26. Karena perbaikan dikembangkan memakai sampel ini, perubahan angka tersebut merupakan hasil pengembangan pada sampel yang sama. **Ini belum mengukur akurasi pada sampel baru.**

## Mengulang pemeriksaan

[Manifest corpus](../evaluation/public-corpus.json) mencatat repo, path, ukuran awal, dan Git blob SHA setiap file. [Ringkasan hasil](../evaluation/pilot-results.json) mencatat hitungan dan batas interpretasi. Kode workflow pihak ketiga tidak disalin ke repo auditor.

Dari folder utama auditor, setelah dependensi terpasang:

```bash
python3 scripts/evaluate_corpus.py --corpus-root /tmp/cha-corpus --download > reports/pilot.json
```

Buat folder `reports` terlebih dahulu jika belum ada. Opsi `--download` meminta pengambilan blob melalui API publik GitHub; batas API atau jaringan dapat menyebabkan status `2`. Script tidak membaca token autentikasi dari environment. Unduhan hanya disimpan setelah cocok dengan Git blob SHA; referensi branch yang dapat berubah tidak digunakan sebagai identitas konten.

Jika file sudah diunduh, ulangi secara offline:

```bash
python3 scripts/evaluate_corpus.py --corpus-root /tmp/cha-corpus > reports/pilot.json
```

Script tetap memverifikasi hash sebelum pemeriksaan. Status `0` berarti proses evaluasi selesai, termasuk bila ada peringatan. Status `2` berarti ada kegagalan mengambil, memverifikasi, atau memindai data. Output bukan baseline kebijakan dan tidak mengubah status CI proyek lain.

Gunakan folder corpus yang berada dalam kendali Anda selama proses berjalan. Script menolak symlink yang ditemukan dan menulis unduhan secara atomik; perlindungan terhadap perubahan folder serentak oleh pihak lain berada di luar cakupannya.

## Hal yang belum diukur

Tidak ada penandaan menyeluruh atas semua kerentanan pada sampel. Karena itu, belum dihitung berapa masalah yang terlewat, tingkat keberhasilan deteksi, atau persentase serangan yang dapat dicegah. Sebelum koreksi hanya tiga jenis aturan menghasilkan peringatan; hasil ini belum membuktikan efektivitas lapangan 19 aturan lainnya.

Evaluasi berikutnya perlu sampel baru yang tidak digunakan untuk mengembangkan aturan, peninjauan independen, dan pengujian variasi platform, shell, runner, serta alur deployment. Sampel ini memberi bukti awal tentang pembacaan file dan satu kelompok peringatan keliru yang diperbaiki; klaim cakupannya dibatasi pada itu.
