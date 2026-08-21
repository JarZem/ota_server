# Přenosný modul JarZem Secure OTA pro ESP-IDF

Tento adresář je jediným zdrojem ESP části zabezpečeného OTA systému. Konkrétní ESP projekty nemají obsahovat kopie provisioningu, OTA CHECKu, downloadu, OTA endpointů ani OTA Zigbee2MQTT converteru. Do projektu se celý `ota_server` připojí jako Git submodule a build použije pouze tuto komponentu.

## Co patří do OTA modulu

OTA modul vlastní:

- certifikátovou identitu zařízení a práci s device private key,
- ověřování Root CA a certifikátu OTA serveru,
- bezpečný provisioning Wi-Fi a adresy OTA serveru,
- stavový automat provisioningu,
- trvalý provisioning context pro následný OTA CHECK,
- podepsaný OTA CHECK,
- pětiminutový jednorázový download token,
- HTTPS stažení, SHA256 kontrolu a zápis OTA partition,
- Zigbee endpoint 10 pro zabezpečený OTA transport,
- Zigbee endpoint 11 pro Enable OTA a Status,
- custom clustery `0xFC00`, `0xFC01` a `0xFC02`,
- bitový význam OTA Statusu,
- OTA část Zigbee2MQTT converteru,
- kontrolu kolizí endpointů a clusterů před buildem,
- automatické vytvoření deployovatelného Zigbee2MQTT balíčku,
- automatické publikování hotového BINu do OTA serveru.

Aplikační projekt vlastní pouze svou funkci: tlačítka, relé, LED výstupy, senzory, aplikační endpointy a svoji část Zigbee2MQTT converteru.

## První integrace nového projektu

Instalátor se spustí jednou nad kořenem ESP-IDF projektu:

```powershell
python external\ota_server\tools\esp_ota\install.py .
```

Pokud submodule ještě neexistuje, první spuštění instalačního skriptu z checkoutu `ota_server` lze udělat i z jiného umístění:

```powershell
python D:\cesta\k\ota_server\tools\esp_ota\install.py D:\Espressif\project\novy_projekt
```

Instalátor:

1. přidá `external/ota_server` jako Git submodule a připne jej na konkrétní commit,
2. vloží do hlavního CMake pouze bootstrap a post-build hook,
3. nikdy neupravuje aplikační Zigbee C zdrojové kódy,
4. připraví oddělený projektový a OTA Zigbee2MQTT converter,
5. u úplně nového zařízení vytvoří unikátní EC P-256 private key a device certifikát podepsaný offline Root CA,
6. odešle do OTA serveru pouze veřejný device certifikát,
7. uloží hash všech souborů identity do `.jarzem_ota/identity.json`,
8. připraví `.jarzem_ota/project.json` s firmware metadaty a adresou publish API.

## Již existující projekt a klíče

Jestli projekt už obsahuje `device_credentials`, instalátor je pouze převezme. Ověří, že private key odpovídá device certifikátu a že certifikát patří k instalované Root CA. Potom vytvoří pouze manifest s hashi.

Existující private key ani certifikát se při tomto kroku nemění.

Pokud je identita neúplná, instalátor skončí chybou. Nesmí chybějící soubor automaticky nahradit novým klíčem.

## Neměnnost identity při dalších buildech

Po první integraci platí tvrdé pravidlo: build smí identitu pouze číst a ověřit.

Každý build před kompilací porovná SHA256 těchto souborů s instalačním manifestem:

- `device_private.pem`,
- `device_cert.pem`,
- `root_ca_cert.pem`,
- `ota_server_cert.pem`.

Pokud něco chybí nebo se hash změnil, build se zastaví. Build nikdy nevytváří nový private key, nikdy neobnovuje certifikát a nikdy automaticky neopravuje identitu.

Device private key se nikdy neposílá do Home Assistantu ani OTA serveru. Je pouze lokálně vložen do výsledného firmware. Root CA private key zůstává offline mimo ESP projekt i OTA server.

## Automatické připojení do Zigbee projektu

Aplikační kód dále používá běžné Espressif funkce:

```c
esp_zb_device_register(ep_list);
esp_zb_core_action_handler_register(project_handler);
```

Linker je při buildu přesměruje přes OTA komponentu. Ta před registrací přidá svoje endpointy 10 a 11 a před aplikační handler vloží obsluhu OTA zpráv. Zprávy, které OTA modulu nepatří, předá beze změny aplikačnímu handleru.

Proto nový projekt nemusí kvůli OTA upravovat vlastní `zigbee.c`.

## Kontrola endpointů a clusterů

Před každým buildem `prebuild_validate.py` prohledá aplikační zdrojové soubory. OTA si rezervuje:

```text
Endpoint 10
Endpoint 11
Cluster 0xFC00
Cluster 0xFC01
Cluster 0xFC02
```

Pokud je použije aplikační projekt, konfigurace se zastaví s názvem souboru a řádkem kolize. Nic se automaticky nepřepíše, protože tichá změna Zigbee datového modelu by nebyla bezpečná.

## Co se děje při běžném buildu

`idf.py build` provede postupně:

```text
ověření neměnné identity
        ↓
kontrola kolizí endpointů a clusterů
        ↓
kompilace aplikačního projektu + připnutého OTA submodulu
        ↓
vytvoření build/zigbee2mqtt/
        ↓
podepsání SHA256 BINu existujícím device private key
        ↓
HTTPS upload BINu a release metadat do OTA serveru
```

Publish request obsahuje device certifikát a ECDSA podpis. OTA server device certifikát ověří proti Root CA a podpis proti veřejnému klíči z certifikátu. Private key neopustí build počítač.

## Zigbee2MQTT converter

Converter je záměrně rozdělený.

Projekt má například:

```text
zigbee2mqtt/remotecontrol7andEncoder.project.mjs
```

Ten zná jen aplikační endpointy.

OTA repo má:

```text
external/ota_server/zigbee2mqtt/jarzem_secure_ota.mjs
```

Ten zná pouze OTA endpointy, clustery, Enable OTA a Status.

Build vytvoří deployovatelný adresář:

```text
build/zigbee2mqtt/
    remotecontrol7andEncoder.mjs
    remotecontrol7andEncoder.project.mjs
    jarzem_secure_ota.mjs
```

Tím se OTA část neverzuje podruhé v aplikačním projektu.

## Aktualizace OTA modulu

Build sám nikdy nedělá `git pull`. Konkrétní commit ESP projektu proto vždy používá konkrétní commit OTA modulu.

Aktualizace je vědomý krok:

```powershell
git -C external/ota_server fetch origin
git -C external/ota_server checkout <novy-commit-nebo-tag>
git add external/ota_server
git commit -m "Update secure OTA module"
```

Po novém clone se submodule obnoví:

```powershell
git submodule update --init --recursive
```

## Provisioning jako stavový automat

Provisioning není posloupnost volně přijímaných zpráv. Každá zpráva je platná jen ve stavu, ve kterém systém očekává právě ji.

Na ESP straně lidsky:

```text
zařízení je v klidu a má poslední funkční provisioning
        ↓ uživatel zapne Enable OTA
zařízení zahájí nový pokus a odešle podepsaný úvodní požadavek
        ↓
čeká na ověřenou výzvu OTA serveru
        ↓ výzva je platná
odešle podepsanou odpověď
        ↓
čeká na zašifrovaný provisioning
        ↓ provisioning je platný a byl uložen
zařízení se vrátí do provisioned stavu,
Enable OTA vypne a odešle provisioning+finished
```

Na OTA serveru:

```text
server je v klidu
        ↓ přijde platný nový úvodní požadavek s vyšším counterem
server odešle výzvu a čeká na odpověď zařízení
        ↓ odpověď je platná
server odešle provisioning a čeká na potvrzení dokončení
        ↓ přijde provisioning+finished
server uloží nový trvalý context a vrátí se do klidu
```

Duplicitní, stará nebo opožděná zpráva, která systém neposouvá do právě očekávaného dalšího stavu, se ignoruje. Neúspěšný nový pokus nemaže poslední funkční provisioning. Nový kryptograficky platný začátek s vyšším counterem může bezpečně zahájit nový pokus místo čekání na starou zaseknutou relaci.

## OTA CHECK a download

OTA CHECK je oddělený od Enable OTA. Enable OTA povoluje provisioning, nikoliv samotnou kontrolu firmware.

Server odešle verzi, třípísmenný kód firmware a nový random. MAC se vypočítá s trvalým contextem posledního úspěšného provisioningu. ESP ověří MAC a porovná nabídnutou verzi s běžícím firmware.

Pokud je firmware novější, obě strany z CHECK randomu a session contextu sestaví stejný jednorázový download token. Token platí maximálně pět minut. Po kompletním úspěšném stažení je grant zneplatněn.

OTA Status je bitové pole, takže významy lze kombinovat:

```text
bit 7  error
bit 6  provisioning
bit 5  firmware
bit 4  verify
bit 3  skipped
bit 2  timeout
bit 1  finished
bit 0  started
```

Například `0x42` znamená provisioning + finished a `0x2A` firmware + skipped + finished.
