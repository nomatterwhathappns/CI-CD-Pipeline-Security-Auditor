# Aturan tambahan CHA021–CHA022

Dua pemeriksaan ini menambah cakupan yang belum ditangani CHA001–CHA020.
Temuan menunjukkan konfigurasi yang perlu ditinjau. Keduanya tidak membuktikan
bahwa serangan telah terjadi atau bahwa runner dapat diambil alih.

## CHA021 — perintah workflow lama diaktifkan kembali

Perintah lama `set-env` dan `add-path` mengubah environment atau jalur pencarian
program melalui output log. GitHub menggantinya dengan file `GITHUB_ENV` dan
`GITHUB_PATH` setelah ditemukan risiko injeksi melalui output tak tepercaya.

Aturan menandai deklarasi `ACTIONS_ALLOW_UNSECURE_COMMANDS` yang efektif bernilai
`true` pada setidaknya satu langkah. Nama variabel diperiksa persis seperti
penulisan huruf besar tersebut. Environment langkah mengalahkan environment job,
dan environment job mengalahkan environment workflow. Deklarasi yang diwarisi
banyak langkah dilaporkan sekali pada lokasi asalnya.

Contoh yang perlu ditinjau:

```yaml
env:
  ACTIONS_ALLOW_UNSECURE_COMMANDS: 'true'
```

Hapus opt-in tersebut dan gunakan file environment untuk nilai yang sesuai:

```yaml
steps:
  - run: echo "REPORT_NAME=example" >> "$GITHUB_ENV"
```

Untuk input dari luar, tetap lakukan validasi nilai dan penanganan multiline.
Menggunakan `GITHUB_ENV` saja belum otomatis menangani injeksi; lihat CHA016.

Batas pemeriksaan:

- Runner menggunakan parsing boolean; `true` tanpa membedakan huruf besar/kecil
  dikenali, sedangkan `1`, `yes`, dan teks lain tidak dianggap mengaktifkan opt-in.
- Boolean YAML serta ekspresi literal sederhana seperti `${{ true }}` dan
  `${{ 'true' }}` dikenali. Ekspresi dinamis belum diselesaikan.
- Environment berupa satu ekspresi dinamis membuat pewarisan di scope tersebut
  belum dapat dipastikan. Deklarasi eksplisit pada scope lebih sempit tetap dapat
  dikenali.
- Override `false` diperhitungkan. Langkah atau job dengan kondisi literal
  `false` yang dikenali dilewati. Kondisi lain belum dievaluasi secara lengkap.
- Environment pada mesin runner, perubahan melalui script, environment internal
  action, dan semua variasi penamaan variabel Windows belum ditelusuri.
- Kecocokan berarti opt-in dikonfigurasi, bukan bukti bahwa perintah lama benar-benar
  dipakai atau bahwa injeksi berhasil dilakukan.

Sumber primer:

- [Pengumuman GitHub mengenai penghentian set-env/add-path](https://github.blog/changelog/2020-10-01-github-actions-deprecating-set-env-and-add-path-commands/).
- [Implementasi runner untuk opt-in dan parsing boolean](https://github.com/actions/runner/blob/main/src/Runner.Worker/ActionCommandManager.cs).

## CHA022 — container job atau service memakai mode privileged

Flag Docker `--privileged` memberikan hak akses luas kepada container dan
mengurangi sejumlah pembatasan isolasinya. Docker menyarankan pemberian kemampuan
spesifik ketika cukup untuk kebutuhan aplikasi.

Aturan memeriksa `jobs.<job>.container.options` dan
`jobs.<job>.services.<service>.options`.

Contoh yang perlu ditinjau:

```yaml
container:
  image: example/image@sha256:<digest-yang-sudah-ditinjau>
  options: --privileged
```

Perbaikan bergantung pada kebutuhan. Hilangkan mode privileged jika tidak
berfungsi penting; jika diperlukan kemampuan tertentu, berikan kemampuan
tersebut secara eksplisit dan tinjau isolasi runner. Contoh pengurangan hak akses:

```yaml
container:
  image: example/image@sha256:<digest-yang-sudah-ditinjau>
  options: --read-only --cap-drop ALL
```

Placeholder digest pada potongan ini harus diganti. Opsi contoh juga harus
disesuaikan dengan aplikasi; mode read-only dapat membuat aplikasi yang perlu
menulis gagal berjalan.

Batas pemeriksaan:

- Hanya opsi literal dengan sintaks yang dikenali diperiksa. Opsi dinamis atau
  sintaks Docker yang tidak dikenali dibiarkan belum dapat dipastikan.
- Quoting dan nilai opsi diperhitungkan. Misalnya `--label "--privileged"` adalah
  nilai label dan tidak ditandai sebagai flag privileged.
- `--privileged=false` dilewati; bila ada beberapa deklarasi boolean, nilai
  terakhir yang dikenali digunakan.
- Aturan tidak menilai seluruh kombinasi capability, mount, user namespace,
  konfigurasi daemon Docker, atau perlindungan tambahan pada runner.
- Penggunaan yang sah, seperti sebagian kebutuhan Docker-in-Docker, tetap dapat
  menghasilkan temuan. Tinjau kebutuhan dan batas aksesnya sebelum menentukan
  pengecualian.
- Script `docker run ...` di dalam `run` belum diperiksa oleh aturan ini.

Sumber primer:

- [GitHub: opsi container pada job](https://docs.github.com/en/actions/how-tos/write-workflows/choose-where-workflows-run/run-jobs-in-a-container#setting-container-resource-options).
- [Docker: dampak flag privileged](https://docs.docker.com/reference/cli/docker/container/run/#escalate-container-privileges---privileged).

## Contoh pengujian

Contoh lengkap ada di `fixtures/rules/CHA021-bad.yml`, `CHA021-good.yml`,
`CHA022-bad.yml`, dan `CHA022-good.yml`. Seluruhnya disimpan di luar folder
workflow aktif dan dipakai sebagai data statis. Digest container dalam fixture
hanya ilustrasi untuk pemeriksaan format.
