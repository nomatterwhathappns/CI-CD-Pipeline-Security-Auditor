# Keamanan auditor

Auditor membaca workflow sebagai data. Program tidak menjalankan script, menghubungi action jarak jauh, atau memverifikasi seluruh pengaturan repository dan runner. Temuan perlu ditinjau; hasil kosong bukan jaminan keamanan.

## Versi dan data kerentanan

Perbaikan dikembangkan pada versi terbaru di branch `main`. Proyek belum memiliki jadwal dukungan versi lama atau SLA respons keamanan. Jika melaporkan masalah, sertakan versi dan commit yang diuji.

Data advisory bawaan adalah snapshot offline terbatas. Tanggal snapshot dan cakupannya ada dalam laporan JSON. Daftar tersebut tidak diperbarui otomatis dan tidak menggantikan pemantauan advisory dari pengelola action.

## Melaporkan kerentanan

Jika tab **Security** repo menyediakan **Report a vulnerability**, gunakan jalur privat tersebut. Ketersediaannya bergantung pada pengaturan pemilik repo. Bila jalur privat belum tersedia, buka issue yang hanya meminta pemilik mengaktifkan jalur pelaporan privat; jangan sertakan detail eksploitasi, secret, atau data privat pada issue publik.

Setelah kanal privat tersedia, sertakan versi/commit, reproduksi minimal dengan data buatan, dampak yang dapat dibuktikan, serta saran perbaikan bila ada. Jangan menggunakan secret sungguhan dalam reproduksi.

## Penanganan data dan kebijakan pemeriksaan

- Nilai kandidat kredensial tidak dimasukkan ke pesan temuan. Hindari menyertakan secret dalam alasan pengecualian, nama file, nama job, atau data konfigurasi lain yang memang tampil dalam laporan.
- Simpan laporan dan baseline sesuai sensitivitas repo. Keduanya memuat metadata struktur proyek, dan file konfigurasi dapat memuat alasan keputusan tim.
- Tinjau perubahan konfigurasi pengecualian dan baseline seperti perubahan kebijakan keamanan. Orang yang bisa mengubahnya dapat mengurangi temuan yang menggagalkan CI.
- Pembatasan input membantu mengurangi risiko terhadap parser. Pembatasan tersebut tidak menjadi bukti bahwa semua bentuk input berbahaya sudah ditangani.
