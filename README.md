# Kuzki kontakt + QR scan tracking

Kontaktna stran je na **https://kuski.qd.je/**.

Vsak fizicni plakat dobi svoj nakljucni ID in QR URL:

```
https://kuski.qd.je/?p=a1b2c3
```

Ob odprtju stran:
1. prebere parameter `p`,
2. takoj odstrani query iz URL-ja brez novega page loada,
3. v ozadju poslje en POST na `https://scan.kuski.qd.je/scan`.

Zato refresh po prvem odprtju ne steje novega skena. Vsak scan ima se nakljucni `scan_id`, zato tudi ponovljen beacon istega odpiranja ni podvojen.

Backend v SQLite hrani samo:
- poster ID,
- cas skena,
- nakljucni scan ID za deduplikacijo.

IP naslov se ne zapisuje v aplikacijsko bazo.

## Hiter deploy na Oracle VPS

### 1. DNS

V DigitalPlat DNS za cono `kuski.qd.je` dodaj:

- Type: `A`
- Name: `scan`
- Value: javni IPv4 Oracle VPS
- TTL: `300`

To ustvari `scan.kuski.qd.je`.

### 2. Backend

Na VPS:

```bash
git clone https://github.com/LukaCek/kuzki-contact.git
cd kuzki-contact/backend
cp .env.example .env
nano .env
```

V `.env` zamenjaj `ADMIN_PASSWORD` z dolgim nakljucnim geslom.

Nato:

```bash
docker compose up -d --build
docker compose ps
```

API je na host portu `8787`.

### 3A. Ce ze uporabljas Nginx Proxy Manager

Dodaj Proxy Host:

- Domain: `scan.kuski.qd.je`
- Forward Host/IP: Oracle VPS host, dosegljiv iz NPM
- Forward Port: `8787`
- Scheme: `http`

Na SSL zavihku zahtevaj nov certifikat in vklopi Force SSL.

Porta 8787 ni treba odpirati v OCI ingress pravilih, ce ga uporablja samo lokalni reverse proxy.

### 3B. Brez obstojecega reverse proxyja

Na voljo je Caddy override. Port 80 in 443 morata biti prosta in dovoljena v OCI firewallu:

```bash
SCAN_DOMAIN=scan.kuski.qd.je docker compose -f docker-compose.yml -f docker-compose.caddy.yml up -d --build
```

Caddy sam pridobi TLS certifikat.

## Test

```bash
curl https://scan.kuski.qd.je/health
```

Pricakovano:

```json
{"status":"ok"}
```

Testni scan:

```bash
curl -X POST "https://scan.kuski.qd.je/scan?p=test12&s=12345678-test"
```

Statistika:

```
https://scan.kuski.qd.je/stats
```

Browser zahteva HTTP Basic uporabnika in geslo iz `.env`.

CSV:

```
https://scan.kuski.qd.je/stats.csv
```

## Nov poster ID

```bash
python3 tools/new_poster.py "Streliska - oglasna deska 1"
```

Primer:

```
ID:  a1b2c3
URL: https://kuski.qd.je/?p=a1b2c3
```

Skript zapisuje lokalno mapiranje ID -> lokacija v `posters.csv`. Datoteka je ignorirana z Gitom, da fizicnih lokacij ne objavljas v javnem repozitoriju.
