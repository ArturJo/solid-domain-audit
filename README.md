# Domain Audit (CLI)

Ein leistungsstarkes CLI-Tool zur automatisierten Analyse und Überprüfung von Domains. Es sammelt umfassende Daten über Registrierung, DNS-Konfiguration, HTTP-Verhalten und TLS-Zertifikate, um einen Überblick über den technischen Status und das Hosting einer Domain zu erhalten.

## Features

Das Tool führt pro Domain folgende Prüfungen durch:

- **RDAP (Domain):** Abfrage von Registrar, Nameservern und Status. (Hinweis: Inhaberdaten sind aufgrund der DSGVO/GDPR meist geschwärzt). Spezielle Unterstützung für `.de` Domains via DENIC.
- **DNS-Analyse:** Ermittlung von IPv4 (A) und IPv6 (AAAA) Records sowie Reverse DNS (rDNS) Abfragen.
- **IP-RDAP:** Identifizierung des IP-Eigentümers/Organisation (hilfreich zur Bestimmung des tatsächlichen Hosters).
- **HTTP/HTTPS-Checks:** Analyse der Redirect-Ketten, Statuscodes und wichtiger Header wie `Server`, `Via` und `X-Powered-By`.
- **TLS-Zertifikat:** Extraktion von Subject, Issuer und Subject Alternative Names (SAN).
- **Provider Guess:** Eine Best-Effort-Heuristik zur Identifizierung des Hostings/Providers basierend auf Nameservern, Headern und TLS-Daten.

## Installation

Stellen Sie sicher, dass Python 3.7+ installiert ist.

```bash
# Virtuelle Umgebung erstellen (optional aber empfohlen)
python3 -m venv .venv
source .venv/bin/activate

# Abhängigkeiten installieren
pip install -r requirements.txt
```

## Verwendung

Das Tool erwartet eine Liste von Domains in einer Textdatei (eine Domain pro Zeile) oder einer JSON-Datei.

```bash
python3 domain_audit.py --in domains.txt --out out
```

### Argumente

- `--in`: Pfad zur Eingabedatei (`.txt` oder `.json`).
- `--out`: Zielverzeichnis für die Ergebnisse (Standard: `out`).
- `--user-agent`: Optionaler Custom User-Agent für HTTP-Anfragen.

## Output

Die Ergebnisse werden im angegebenen Ausgabeordner in zwei Formaten gespeichert:

1. **`out/domains_audit.csv`**: Eine tabellarische Übersicht, ideal für den Import in Excel oder Google Sheets.
2. **`out/domains_audit.json`**: Vollständige Rohdaten inklusive detaillierter RDAP-Antworten für die Weiterverarbeitung.

## Hinweise

- **Datenschutz:** Personenbezogene Daten des Domaininhabers sind oft nicht öffentlich zugänglich (WHOIS/RDAP Privacy).
- **Heuristik:** Die Provider-Erkennung (`provider_guess`) basiert auf Mustern und kann in Einzelfällen ungenau sein.
- **Netzwerk:** Für die RDAP- und DNS-Abfragen ist eine aktive Internetverbindung erforderlich.
