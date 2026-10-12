# Kuzki kontakt + QR scan tracking

Kontaktna stran je na **https://kuski.qd.je/**.

Vsak fizicni plakat dobi svoj nakljucni ID in QR URL:

```
https://kuski.qd.je/?p=a1b2c3
```

Ob odprtju stran:
1. prebere parameter `p`,
2. takoj odstrani query iz URL-ja brez novega page loada,
3. v ozadju poslje en POST na `https://qr-pski-skenirano.cekluka.com/scan`.

Zato refresh po prvem odprtju ne steje novega skena. Vsak scan ima se nakljucni `scan_id`, zato tudi ponovljen beacon istega odpiranja ni podvojen.

Backend v SQLite hrani skene in dnevnik zahtevkov `POST /scan`:
- ID plakata in nakljucni ID zahtevka,
- cas zahtevka in rezultat (`counted`, `duplicate` ali `invalid_*`),
- HTTP status.

IP naslov se ne zapisuje v aplikacijsko bazo. Za osnovno diagnostiko se shranijo User-Agent, Accept-Language in omejeni Cloudflare Client Hints/drzava, ce so podani.

## Hiter deploy na Oracle VPS

### 1. DNS

V Cloudflare DNS za `cekluka.com` dodaj zapis:

- Type: `A`
- Name: `qr-pski-skenirano`
- Value: `130.61.150.14`
- Proxy status: `Proxied` (deluje tudi `DNS only`).

To ustvari `qr-pski-skenirano.cekluka.com`.

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

- Domain: `qr-pski-skenirano.cekluka.com`
- Scheme: `http`
- Forward Hostname / IP: `kuzki-scan`
- Forward Port: `8000`

NPM in `kuzki-scan` morata biti na istem Docker omrezju `proxy`.
Ce nista, se lahko uporabi zasebni IP VPS in gostiteljski port `8787`.

Na SSL zavihku zahtevaj nov certifikat in vklopi Force SSL.

Porta 8787 ni treba odpirati v OCI ingress pravilih, ce ga uporablja samo lokalni reverse proxy.

### 3B. Brez obstojecega reverse proxyja

Na voljo je Caddy override. Port 80 in 443 morata biti prosta in dovoljena v OCI firewallu:

```bash
SCAN_DOMAIN=qr-pski-skenirano.cekluka.com docker compose -f docker-compose.yml -f docker-compose.caddy.yml up -d --build
```

Caddy sam pridobi TLS certifikat.

## Test

```bash
curl https://qr-pski-skenirano.cekluka.com/health
```

Pricakovano:

```json
{"status":"ok"}
```

Testni scan:

```bash
curl -X POST "https://qr-pski-skenirano.cekluka.com/scan?p=test12&s=12345678-test"
```

Statistika:

```
https://qr-pski-skenirano.cekluka.com/stats
```

Browser zahteva HTTP Basic uporabnika in geslo iz `.env`.

CSV:

```
https://qr-pski-skenirano.cekluka.com/stats.csv
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

## Posamezni zahtevki

Odpri zaščiteno statistiko na `https://qr-pski-skenirano.cekluka.com/stats`.
Na zavihku **Posamezni zahtevki** (`/stats/requests`) so vsi
`POST /scan` zahtevki, tudi podvojeni in neveljavni, po 50 na stran,
z najnovejšimi na vrhu. Beležijo se čas (UTC), ID plakata, naključni
ID zahtevka, rezultat in HTTP status. IP naslovov, uporabniških agentov
in prijavnih podatkov ne beležimo v aplikacijski bazi.

Ob prvi uporabi po posodobitvi se prej obstoječi uspešni skeni
samodejno vnesejo v zgodovino zahtevkov. Preteklih podvojenih/neveljavnih
zahtevkov ni mogoče rekonstruirati. Zahtevki, ki niso `POST /scan`
(npr. `/health`, `/stats`), se ne beležijo.

Za posodobitev:
```bash
cd ~/docker/kuzki-contact
git pull --ff-only
cd backend
docker compose up -d --build
```


## Poimenovanje plakatov

V zaščiteni administraciji **https://qr-pski-skenirano.cekluka.com/stats/posters**
je tretji zavihek **Plakati**. Vnesi obstoječi ID plakata in opis (npr.
`abc123` → `Knjižnica CTK`), nato Shrani. Obstoječo oznako lahko
kadarkoli spremeniš. Če pustiš polje ID prazno, sistem ustvari nov
naključni šestmestni šestnajstiški ID. V tabeli je tudi URL QR-kode
`https://kuski.qd.je/?p=abc123`. **Sliko QR-kode je treba ustvariti
s tem URL-jem**; zgolj preimenovanje ne spreminja že natisnjenih QR-kod.

Ime se prikazuje v **Pregledu**, **Posameznih zahtevkih** in v izvozu CSV.
Obstoječi skeni in podatki ostanejo v SQLite volumnu.

## Metapodatki in povezovanje obiskov

Za vsako zahtevo `POST /scan` se poleg trenutnih podatkov beležijo:
- **User-Agent:** tip/brskalnik/operacijski sistem, kadar ga brskalnik poda;
- **Accept-Language:** jezik;
- **CF-IPCountry:** okvirna država, če jo Cloudflare posreduje;
- **Sec-CH-UA** in sorodni Client Hints, kadar jih brskalnik pošlje.

To niso zanesljivi identifikatorji posameznega telefona. IP-ja backend
ne shranjuje.

Na javni strani je neobvezna, jasno označena **privolitev za prepoznavanje
ponovnih obiskov**. Brez nje se skeni štejejo kot prej. Ob privolitvi
se v `localStorage` ustvari naključni identifikator brskalnika in
pošljejo omejene dodatne lastnosti, ki ne potrebujejo sistemskih dovoljenj:
jezik, časovni pas, platforma, mere zaslona in okna, DPR, globina barv,
podpora dotiku, število logičnih jeder, približen pomnilnik in vrsta
omrežja. Nekateri brskalniki jih ne razkrijejo.

V zavihku **Posamezni zahtevki** se isti identifikator lahko klikne
za prikaz zahtevkov iz istega brskalnika. To **ni dokaz, da gre za isti
fizični telefon**: brskalnik lahko shrambo izbriše, jo blokira ali uporabi
drugo napravo. Obiskovalec lahko soglasje prekliče; uporabniški del
izbriše lokalni ID in prek `/privacy/forget` zahteva izbris identifikatorja
ter prostovoljnih podatkov naprave, ne pa agregatnega števila skenov.

V Sloveniji so trajni analitični identifikatorji in fingerprinting praviloma
vezani na predhodno privolitev; samega sistemskega vprašanja za dovoljenja
ni dovoljeno zamenjevati s pravno privolitvijo. Pred javno rabo preveri
politiko zasebnosti in obdobje hrambe.

### Posodobitev na Oracle VPS

```bash
cd ~/docker/kuzki-contact
git pull --ff-only
cd backend
docker compose up -d --build
```

Testna koda plakata se mora pojaviti v `/stats/posters` in `/stats`.
Nova baza se migrira samodejno brez brisanja dosedanjih skenov.
