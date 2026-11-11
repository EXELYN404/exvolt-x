# Keamanan EXVOLT X

## Penggunaan yang sah
EXVOLT X adalah alat pengujian keamanan. Gunakan hanya pada sistem milik Anda atau dengan izin tertulis pemiliknya.
Pengguna bertanggung jawab atas penggunaannya. Alat ini tidak memiliki fungsi siluman, pencurian kredensial, atau aksi destruktif otomatis.

## Model keamanan
- **Localhost secara default**: UI di `127.0.0.1:8080`, proxy di `127.0.0.1:8081`. Bind non-localhost ditolak kecuali `server.auth_token` (≥16 karakter)
  disetel untuk UI, dan `proxy.allow_remote` diaktifkan eksplisit untuk proxy (proxy tidak punya autentikasi).
- **Scope wajib**: Repeater, Intruder, redirect, dan probe TLS hanya berjalan untuk target yang cocok aturan *include* dan tidak terkena *exclude*.
  Scope kosong = tidak ada target berwenang. Intruder juga menuntut konfirmasi manual `host:port`, batas concurrency/rate/jumlah request,
  dan memeriksa ulang setiap request: payload tidak dapat mengalihkan ke host lain.
- **Perlindungan UI/API**: validasi header `Host` (anti DNS-rebinding), pemeriksaan `Origin` + header `X-Requested-With` (anti CSRF),
  token via cookie `HttpOnly; SameSite=Strict`, CSP ketat (`script-src 'self'`, tanpa inline), `X-Frame-Options: DENY`, `nosniff`, `no-referrer`.
  Semua data dari lalu lintas ditampilkan dengan `textContent` (anti XSS); laporan HTML di-escape.
- **Sertifikat**: CA lokal (ECDSA P-256, `pathlen=0`) dibuat pada eksekusi pertama; kunci privat `certificates/ca.key` berizin 0600.
  Siapa pun yang memegang kunci itu dapat menyadap lalu lintas browser yang memercayai CA ini. Instal hanya di profil pengujian,
  jangan bagikan folder `certificates/`, dan hapus CA setelah selesai.
- **Data**: riwayat, sesi, dan laporan disimpan lokal di `data/` dan dapat memuat data sensitif (cookie, token, kredensial dari lalu lintas).
  Nilai cookie disamarkan pada bukti temuan, tetapi riwayat dan ekspor traffic/sesi menyimpan data mentah. Lindungi folder ini.
- **Tanpa telemetri**, tanpa unggahan otomatis, tanpa layanan cloud.
- **Ekspor**: nama berkas disanitasi; CSV memitigasi formula injection; impor sesi/scope divalidasi dan atomik.
- **Verifikasi TLS upstream** aktif secara default (`proxy.verify_upstream`).

## Pelaporan celah
Laporkan kerentanan EXVOLT X secara privat kepada EXELYN404 lewat fitur *Security advisories* repositori GitHub proyek; sertakan langkah reproduksi dan versi.
