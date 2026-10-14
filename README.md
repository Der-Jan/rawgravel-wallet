# RAWGRAVEL Member Wallet

Website zum Erstellen signierter Apple-Wallet-Mitgliedskarten aus Name, Mitgliedsnummer und Gültigkeitsdatum. Mit deutscher Eingabemaske, Live-Kartenvorschau und QR-Code.

## Docker Compose

Die Compose-Datei nutzt das vorhandene externe Netzwerk `public24` und Traefik mit `websecure` und dem Zertifikatsresolver `lealpn`. Domain und Netzwerk bei Bedarf in `compose.yaml` anpassen.

1. Repository klonen.
2. `secrets/wallet.json` mit folgenden Werten anlegen:

```json
{
  "PASS_CERTIFICATE_PEM": "…",
  "PASS_PRIVATE_KEY_PEM": "…",
  "APPLE_WWDR_CERTIFICATE_PEM": "…",
  "PASS_TYPE_IDENTIFIER": "pass.com.example.rawgravel",
  "APPLE_TEAM_IDENTIFIER": "…"
}
```

Benötigt werden ein gültiges Apple-Pass-Type-ID-Zertifikat, der dazugehörige RSA-Schlüssel und das passende Apple-WWDR-Zertifikat. PEM-Werte unterstützen echte Zeilenumbrüche und literale `\n`. Private Schlüssel ausschließlich in der Secret-Datei speichern.

3. Dateirechte setzen und starten:

```sh
chmod 700 secrets
sudo chown root:1000 secrets/wallet.json
sudo chmod 640 secrets/wallet.json
docker compose up -d --build
```

Der Container läuft als UID/GID 1000 und liest die Secret-Datei unter `/run/secrets/wallet.json`. Es wird kein Host-Port veröffentlicht.

Die Compose-Datei ist für öffentlichen Zugang konfiguriert. Der Generator signiert frei eingegebene Daten und prüft keine Mitgliedschaft gegen eine Datenbank. Optional: `PUBLIC_ACCESS` auf `false` setzen und `ADMIN_BASIC_AUTH` als `benutzer:passwort` in `wallet.json` ergänzen.

## Entwicklung und Tests

Node.js 22 oder neuer:

```sh
npm ci
npm test
```

`npm run build` erzeugt den gebündelten Server in `worker/index.js`. Der Docker-Build übernimmt diesen Schritt. Tests prüfen Eingaben, Ablaufdaten, Herkunftsprüfung, Pass-Paket, Prüfsummen und die CMS-Signatur. Für den Signaturtest wird `openssl` benötigt.

## Verhalten

- QR-Code und Seriennummer entsprechen der Mitgliedsnummer; dieselbe Nummer bezeichnet dieselbe Wallet-Karte.
- Das Ablaufdatum endet um 23:59:59 Uhr in `Europe/Berlin`.
- Der Status gilt bei Ausstellung. Automatische Wallet-Updates sind nicht eingerichtet.
- Die Anwendung speichert keine Mitgliedsdaten.
- Apple Wallet verwendet ein Generic-Pass-Layout. Höhenlinien erscheinen in der Website-Vorschau; das Logo ist anhand der Vorlage nachgezeichnet.
- `/healthz` prüft den Prozess, `/api/status` die Vollständigkeit der Signierungskonfiguration.

Die Pass-Erzeugung verwendet `node-forge` und `fflate`. Die Zertifikatsignatur wird mit Web Crypto geprüft; die Pass-Signatur wird als abgetrennte PKCS#7/CMS-Signatur erstellt.

Betriebsinformationen: [DOCKER-DEPLOYMENT.md](DOCKER-DEPLOYMENT.md).

## Abhängigkeiten

`npm audit` meldet derzeit eine Sicherheitslücke in der RSA-Signaturprüfung von `node-forge`. Die Anwendung verwendet für die Zertifikatsprüfung Web Crypto statt dieser betroffenen Prüfroutine. Abhängigkeitsupdates sollten regelmäßig geprüft werden.
