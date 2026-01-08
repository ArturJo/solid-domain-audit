# Domain Audit (CLI)

Dieses kleine Tool liest Domains aus `domains.txt` (oder JSON) und sammelt pro Domain:
- RDAP (Registrar, Nameserver, Status; Owner/Registrant oft wegen GDPR redacted)
- DNS A/AAAA + Reverse DNS
- HTTP/HTTPS Redirect-Ketten + wichtige Header (Server/Via/X-Powered-By)
- TLS-Zertifikat (Subject/Issuer/SAN)
- **Provider Guess** (Heuristik aus Nameserver/Headers/TLS/RDNS, Best-Effort)

## Installation

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Ausführen

```bash
python3 domain_audit.py --in domains.txt --out out
```

## Output

- `out/domains_audit.csv` (Excel-freundlich)
- `out/domains_audit.json` (vollständige Rohdaten/Details)

## Hinweise

- „Wem gehört die Domain“ ist häufig **nicht** öffentlich verfügbar (WHOIS/RDAP Privacy).
- Der `provider_guess` ist eine Heuristik und kann falsch liegen.
