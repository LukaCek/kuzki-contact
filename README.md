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

Backend v SQLite hrani lokacije, njihove flierje in dnevnik zahtevkov `POST /scan`:
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


## Lokacije, flierji in statistika (15 na lokacijo)

Model podatkov: **lokacija (ime)** -> **do 15 flierjev** -> **QR ID vsakega flierja** -> **zgodovina skenov**.
QR-ID in njegov URL ostaneta takšna kot doslej: `https://kuski.qd.je/?p=ID`.
Ime lokacije je povezano z ID-jem **na backendu**; ni treba spreminjati
QR naslova, ker se lokacija razreši iz baze. Če želiš ime lokacije tudi
natisniti na flier, ga prenesi iz CSV inventarja in vključi v pripravo
za tisk; HTML kontaktne strani ne dodaja lokacije na sliko plakata.

V zaščiteni administraciji
`https://qr-pski-skenirano.cekluka.com/stats/posters`:

1. **Dodaj lokacijo**: vpiši ime (npr. Knjižnica CTK).
   - **Ustvari 15 flierjev**: sistem ustvari 15 različnih kriptografsko
     naključnih QR-ID-jev, povezanih s to lokacijo.
   - **Samo lokacijo**: ustvari prazno lokacijo, če že imaš natisnjene
     unikatne QR-kode in jih želiš dodati s kamero.
2. **+ Dodaj flier**: izberi/vpiši lokacijo in skeniraj QR. Skener
   **ne odpre QR povezave** in zato ne poveča števila obiskov.
   Podpira tudi fotografijo ali lepljenje povezave.
3. V tabeli lahko spremeniš lokacijo posameznega flierja.
   Če ima ciljna lokacija že 15 registriranih flierjev, backend vrne
   HTTP **409** in spremembe ne izvede. Pri ponovnem vpisu istega flierja
   se število ne poveča.

**Inventar CSV:** `/stats/flyers.csv` (za prijavljenega administratorja):
`location,flyer_id,qr_url,scans`. To je podlaga za pripravo 15
različnih fizičnih flierjev za tisk. V CSV niso obiskani URL-ji in
izvoz ne povzroči novih skenov.

**Pregled:** `/stats` prikazuje posebej (a) skupne skene po lokaciji in
število njenih flierjev ter (b) skene za vsak posamezen QR-ID.
`/stats/requests` prikazuje pripadajoče ime lokacije v posameznem
zahtevku, `/stats.csv` pa ima stolpec `location`.
Če flier premakneš na drugo lokacijo, statistika njegovo dosedanjo
zgodovino prikaže pod **trenutno** lokacijo.

**Migracija stare baze:** Ob prvem zagonu se doda tabela `locations`
in stolpec `poster_labels.location_id`; stare oznake se samodejno
pretvorijo v lokacije in dodelijo obstoječim QR-ID-jem. Stari skeni
in logi zahtevkov ostanejo. Lokacije primerjamo z Unicode NFC/casefold
(npr. `Knjižnica CTK` in `KNJIŽNICA CTK` se ne podvojita).
`scan-data` Docker volume se ne briše.

### Namestitev

```bash
cd ~/docker/kuzki-contact
git pull --ff-only
cd backend
docker compose up -d --build
docker compose ps
```

Preveri `/stats/posters`; za dodatno preverjanje lahko v repozitoriju
zaženeš `python -m unittest discover -s backend/tests -v`, če imaš
nameščene Python odvisnosti. Pred prvo nadgradnjo je priporočljiva
varnostna kopija Docker volumna z bazo.

## Metapodatki in povezovanje obiskov

Za vsako zahtevo `POST /scan` se poleg trenutnih podatkov beležijo:
- **User-Agent:** tip/brskalnik/operacijski sistem, kadar ga brskalnik poda;
- **Accept-Language:** jezik;
- **CF-IPCountry:** okvirna država, če jo Cloudflare posreduje;
- **Sec-CH-UA** in sorodni Client Hints, kadar jih brskalnik pošlje.

To niso zanesljivi identifikatorji posameznega telefona. IP-ja backend
ne shranjuje.

Javna kontaktna stran ima prenovljen prikaz v `index.html` in
funkcionalnosti v `app.js`. Na **vrhu `app.js`** je stikalo:

```javascript
const ENABLE_DEVICE_ANALYTICS = false;
```

Ko je `false`, je prikaz privolitve odstranjen iz uporabniškega vmesnika;
ne uporablja se `localStorage`, ne pošiljajo se trajni identifikatorji
brskalnika in dodatne lastnosti naprave. **Osnovni `POST /scan` in
štetje QR-skenov delujeta še naprej**, backend pa beleži standardne
tehnične podatke HTTP zahtevka, opisane zgoraj.

Če stikalo v prihodnje spremeniš v `true`, se vrne **prostovoljna
izbira** za dodatno analitiko, nikakor pa to ne pomeni samodejnega
zbiranja brez privolitve. Šele po privolitvi se v `localStorage`
ustvari naključni identifikator brskalnika in pošljejo omejene dodatne
lastnosti naprave: jezik, časovni pas, platforma, mere zaslona in okna,
DPR, globina barv, podpora dotiku, število logičnih jeder, približen
pomnilnik in vrsta omrežja. Nekateri brskalniki jih ne razkrijejo.

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


### Kamera v administraciji

Kamera se vključi šele po pritisku gumba in dovoljenju brskalnika.
Naloži se `html5-qrcode` (različica 2.3.8) iz CDN na zahtevo.
Za kamero je potreben HTTPS; skeniranje fotografije in ročni vnos
QR naslova sta alternativi. Skenirani naslovi se **nikoli ne odpirajo**.
Sprejete so le veljavne povezave oblike
`https://kuski.qd.je/?p=ID`. Ime se shrani na VPS v SQLite
v tabelo `poster_labels`, zaščiteno z obstoječo prijavo in CSRF.

## Kontaktna stran

- Prenovljen, odziven izgled (`index.html`), z letakom `mateja-flyer.png`.
- Tačka ima vse **štiri prste**, WhatsApp in Viber uporabljata SVG logotipa
  iz Simple Icons, ostale akcije pa preverjene ikone iz Lucide.
- Telefonski kontakt ostaja `+38670337710`; e-pošta je
  `sprehodkuzkov.lj@gmail.com`.
- Gumb **Deli kontakt** ne deli naključnega ID-ja plakata `?p=...`.
- JavaScript je v `app.js`, kjer se dodatno zbiranje podatkov
  vklopi/izklopi s konstanto `ENABLE_DEVICE_ANALYTICS`.
- Frontend regresijski testi: `node --test tests/contact.test.cjs`.

Kontaktna stran se objavlja z GitHub Pages; za te spremembe ni potrebno
ponovno graditi Docker backenda.
