# Hosting Monitor

`hosting_monitor.sh` adalah utilitas Bash read-only untuk memantau server hosting cPanel, DirectAdmin, atau Linux generik. Script dapat dijalankan untuk melihat file besar, sertifikat SSL publik yang sudah kedaluwarsa, dan status layanan hosting terpilih. Script tidak mengubah file hosting atau keadaan layanan; keluarannya berupa laporan dan metrik Prometheus.

## Persyaratan

- Server Linux dengan Bash dan perintah sistem yang dibutuhkan tiap mode (`find`, `sort`, `head` untuk disk; `openssl` dan `timeout` untuk SSL; `systemctl` untuk layanan).
- Hak akses `root`.
- Untuk metrik dashboard, Node Exporter harus membaca direktori textfile collector yang digunakan script, dan Prometheus harus mengumpulkan metrik tersebut.

Script mendeteksi cPanel dan DirectAdmin secara otomatis. Pemeriksaan layanan cPanel menggunakan WHM API jika tersedia, lalu beralih ke systemd bila tidak dapat digunakan. DirectAdmin dan Linux generik menggunakan systemd.

## Penggunaan

Jalankan dari server Linux:

```bash
chmod +x hosting_monitor.sh
sudo ./hosting_monitor.sh --help
```

Perintah utama:

```bash
sudo ./hosting_monitor.sh                   # Jalankan semua mode, masing-masing membuat laporan
sudo ./hosting_monitor.sh disk              # File minimal 1G, maksimum 30 hasil
sudo ./hosting_monitor.sh disk 100M 10      # File minimal 100M, maksimum 10 hasil
sudo ./hosting_monitor.sh disk 1G 50
sudo ./hosting_monitor.sh ssl               # Sertifikat publik kedaluwarsa
sudo ./hosting_monitor.sh service           # Status layanan hosting terpilih
```

Ukuran disk menerima bilangan bulat dengan satuan `K`, `M`, `G`, atau `T`; jumlah hasil harus antara 1 dan 1000. Pemindaian disk hanya mencakup file reguler pada `/home`, `/var/log`, `/var/lib/mysql`, dan `/tmp`, tanpa menyeberangi filesystem (`-xdev`), serta dijalankan dengan prioritas CPU/I/O rendah.

Pemeriksaan SSL menggunakan koneksi TLS keluar ke port 443 dengan SNI dan batas waktu 10 detik. Hasilnya mencerminkan sertifikat yang disajikan endpoint publik yang dicapai, sehingga bila domain berada di belakang Cloudflare, WAF, atau load balancer, sertifikat origin lokal belum tentu yang diperiksa.

Laporan disimpan per mode di `/var/log/hosting-monitor/` dengan nama `report-YYYYMMDD-<mode>.log`. Mode tanpa argumen membuat laporan disk, SSL, dan service secara terpisah. Script juga menulis metrik secara atomik ke direktori textfile collector Node Exporter, secara default `/var/lib/node_exporter/textfile_collector/`. Direktori dapat diubah melalui `NODE_EXPORTER_TEXTFILE_DIR`. File metriknya adalah:

- `hosting_monitor_large_files.prom`
- `hosting_monitor_services.prom`
- `hosting_monitor_ssl.prom`

## Dashboard Grafana

`dashboard_grafana.json` mendefinisikan dashboard dengan rentang waktu awal enam jam terakhir dan refresh otomatis setiap menit. Variabel dashboard memilih server (`server`) dan instance Node Exporter (`instance`); panel Prometheus difilter berdasarkan instance terpilih.

Dashboard disusun dalam tiga bagian:

1. **Large files** — empat kartu ringkasan menampilkan jumlah file besar, ambang ukuran scan, file terbesar, dan waktu sejak scan terakhir. Tabel **TOP 10 LARGEST FILES** mencantumkan ukuran, waktu modifikasi, pemilik, lokasi, dan path.
2. **Services** — kartu total layanan, layanan aktif, down, dan disabled, disertai tabel status per layanan dan kategorinya.
3. **SSL monitoring** — kartu jumlah sertifikat kedaluwarsa dan tabel domain terdampak, tanggal kedaluwarsa, serta lamanya sertifikat kedaluwarsa.

Dashboard membutuhkan metrik yang diekspor script dan dikumpulkan Prometheus. Khususnya, daftar file besar menampilkan maksimum 10 baris; nilai ini ditetapkan di query dashboard, terlepas dari jumlah yang dicetak pada laporan script.
