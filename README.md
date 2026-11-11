# EXVOLT X

Platform pengujian keamanan web berbasis browser, dipublikasikan oleh **EXELYN404** (lisensi MIT).
Backend Python + Starlette/Uvicorn, SQLite, frontend HTML/CSS/JavaScript murni (tanpa build, tanpa Node.js).

Semua fitur bekerja pada data nyata: proxy menangkap lalu lintas sungguhan, Repeater/Intruder mengirim request sungguhan,
scanner hanya melaporkan temuan yang punya bukti dari respons yang benar-benar diterima. Tidak ada data contoh, trafik
buatan, atau statistik palsu.

> **Hanya uji sistem yang Anda miliki atau yang Anda punya izin tertulis untuk diuji.** Lihat [SECURITY.md](SECURITY.md).

## Instalasi

Butuh Python 3.10+ (Linux).

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 main.py
```

Buka <http://127.0.0.1:8080>. Opsi: `python3 main.py --port 9000`, `--host`, `--config`.

Catatan teknis: API dibangun di atas **Starlette** (fondasi FastAPI) tanpa lapisan FastAPI; klien HTTP memakai `http.client`
stdlib agar header dikirim persis seperti yang diketik (httpx dipakai hanya untuk tes). Tanpa pustaka `websockets`,
UI otomatis memakai Server-Sent Events untuk update real-time.

## Alur kerja cepat

1. **Scope** → tambah aturan *include* untuk target Anda (mis. domain `localhost`). Tanpa include, semua aksi aktif ditolak.
2. **Proxy** → *Mulai Proxy* (default `127.0.0.1:8081`). Atur proxy HTTP/HTTPS browser ke alamat itu.
3. Instal CA: unduh dari tab *Koneksi & CA* (atau `http://127.0.0.1:8081/ca.pem` lewat proxy) dan impor sebagai
   Authority di profil browser **khusus pengujian**. CA dibuat lokal pada eksekusi pertama dan disimpan di `certificates/` (izin 0600).
4. Telusuri target. Request muncul di **Riwayat HTTP**; temuan pasif di **Scanner**; WebSocket di **WebSocket**.
5. Klik kanan entri riwayat → kirim ke **Repeater**, **Comparer**, **Sequencer**, atau tambah host ke scope.
6. **Laporan** → buat HTML/JSON dari temuan nyata. **Pengaturan** → simpan/muat/ekspor sesi.

## Modul

| Modul | Fungsi |
|---|---|
| Ringkasan | Statistik nyata dari database: aktivitas 60 menit, distribusi status/metode, temuan, topologi host |
| Proxy | Listener HTTP/HTTPS (MITM TLS), intercept, edit request mentah, forward/drop, log, info CA |
| Riwayat HTTP | Pencarian, filter, sort, paginasi, Raw/Pretty/Header/Body, ekspor JSON/HAR, hapus; tersimpan di SQLite |
| Repeater | Banyak tab, editor mentah + URL bar, redirect opsional, simpan/muat, riwayat; patuh scope |
| Intruder | Sniper/Battering ram/Pitchfork/Cluster bomb, konfirmasi target, batas concurrency & rate, Stop yang membatalkan request berjalan, ekspor CSV/JSON |
| Scanner | Analisis pasif (header, cookie, HTTPS/TLS, kebocoran info, CORS, mixed content, dll.) + probe TLS langsung (dalam scope) |
| Sequencer | Tangkap token dari lalu lintas proxy/riwayat/manual; entropi, uji bit, duplikat, pola numerik |
| Decoder | URL, Base64, Base64URL, Hex, HTML, Unicode, JSON, inspeksi JWT, SHA-1/256/512, MD5 |
| Comparer | Diff teks/JSON, abaikan whitespace/huruf besar, ekspor HTML/JSON, muat dari riwayat |
| WebSocket | Koneksi & pesan tertangkap (masuk/keluar), pencarian, filter, ekspor |
| Scope | Aturan include/exclude: domain (wildcard), IP/CIDR, port, URL/regex; impor/ekspor; uji URL |
| Laporan | HTML & JSON, bukti per temuan, ekspor traffic |
| Pengaturan | Semua konfigurasi, sesi (simpan/muat/impor/ekspor/autosave/pemulihan), CA |

## API

REST di `/api/*` (lihat `exvolt/api/app.py`), contoh: `GET /api/health`, `GET /api/proxy/status`, `POST /api/proxy/start`,
`POST /api/proxy/intercept`, `GET /api/history`, `POST /api/repeater/send`, `POST /api/decoder/encode`, `POST /api/comparer/compare`,
`GET|POST /api/scope`, `GET /api/scanner/findings`, `GET /api/reports`. Real-time: WebSocket `/api/ws` (atau SSE `/api/events`).
Metode mengubah-state wajib header `X-Requested-With: exvolt`.

## Pengujian

```bash
pip install -r requirements-dev.txt
python3 -m pytest tests -q
```

Tes memakai target `127.0.0.1` lokal: dekoder, comparer, scope, scanner, proxy HTTP/HTTPS/intercept/WebSocket, repeater, intruder
(termasuk stop dan pembatasan target), sequencer, sesi, laporan, keamanan API, dan smoke test frontend (referensi berkas,
sintaks JS, kepatuhan CSP).

## Troubleshooting

| Gejala | Solusi |
|---|---|
| `Dependensi belum terpasang` | Aktifkan venv lalu `pip install -r requirements.txt` |
| `Address already in use` | Ganti port: `python3 main.py --port 9000`; port proxy di Pengaturan/Proxy |
| Browser: peringatan sertifikat | CA EXVOLT X belum diimpor sebagai Authority di profil browser tersebut |
| Situs tertentu gagal setelah diproksi | Situs memakai certificate pinning; tambahkan host ke *Host tanpa intersepsi* |
| `request ditolak: di luar scope` | Tambahkan target ke Scope (include), atau periksa aturan exclude |
| Update live berhenti | Muat ulang halaman; periksa log proxy |
| Menolak start non-localhost | Setel `server.auth_token` (≥16 karakter) di `config.yaml` |
| Lupa token | Kosongkan `server.auth_token` di `config.yaml` (saat server mati) |

## Struktur

`main.py` (entry) · `exvolt/core` (proxy, scope, database, CA, sesi) · `exvolt/modules` (decoder, comparer, scanner, repeater, intruder, sequencer, reporting) ·
`exvolt/api` (REST, keamanan) · `web/` (UI statis) · `data/` (SQLite, sesi, laporan) · `certificates/` (CA) · `tests/`.

Batasan saat ini: proxy HTTP/1.1 (ALPN dipaksa http/1.1; HTTP/2 dan HTTP/3 tidak diintersepsi), dekompresi Brotli butuh paket `brotli` opsional,
scanner aktif (payload injeksi) belum ada, hanya scanner pasif dan probe TLS.
