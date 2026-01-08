#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
domain_audit.py
---------------
CLI tool to audit domains:
- RDAP (registrar, nameservers, status; registrant often redacted by GDPR)
- DNS A/AAAA + reverse DNS
- HTTP/HTTPS redirect chains + key headers
- TLS certificate subject/issuer/SAN
Outputs:
- CSV (Excel-friendly)
- JSON (full raw details per domain)

Usage:
  pip install -r requirements.txt
  python3 domain_audit.py --in domains.txt --out out
"""

import argparse
import csv
import json
import re
import socket
import ssl
import sys
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Tuple

import requests

IANA_RDAP_BOOTSTRAP = "https://data.iana.org/rdap/dns.json"

# --- Helpers -----------------------------------------------------------------

DOMAIN_CLEAN_RE = re.compile(r"^\s*([^#\s(]+)")


def to_punycode(domain: str) -> str:
    domain = domain.strip().rstrip(".")
    try:
        return domain.encode("idna").decode("ascii")
    except Exception:
        return domain


def split_tld(domain_ascii: str) -> str:
    parts = domain_ascii.split(".")
    return parts[-1].lower() if len(parts) > 1 else ""


def safe_join(values: List[str], sep: str = " | ") -> str:
    vals = [v for v in values if v]
    return sep.join(vals)


def now_iso() -> str:
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


# --- Input -------------------------------------------------------------------

def read_domains(path: Path) -> List[str]:
    if not path.exists():
        raise FileNotFoundError(path)

    if path.suffix.lower() == ".json":
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, list):
            return [str(x).strip() for x in data if str(x).strip()]
        raise ValueError("JSON must be a list of domains.")
    else:
        domains: List[str] = []
        for line in path.read_text(encoding="utf-8").splitlines():
            m = DOMAIN_CLEAN_RE.match(line)
            if not m:
                continue
            d = m.group(1).strip()
            if d:
                domains.append(d)
        return domains


# --- RDAP --------------------------------------------------------------------

class RdapBootstrap:
    def __init__(self, session: requests.Session):
        self.session = session
        self.tld_to_services: Dict[str, List[str]] = {}

    def load(self) -> None:
        r = self.session.get(IANA_RDAP_BOOTSTRAP, timeout=20)
        r.raise_for_status()
        data = r.json()
        services = data.get("services", [])
        mapping: Dict[str, List[str]] = {}
        for item in services:
            if not (isinstance(item, list) and len(item) == 2):
                continue
            tlds, urls = item
            if not isinstance(tlds, list) or not isinstance(urls, list):
                continue
            for tld in tlds:
                mapping[str(tld).lower()] = [str(u).rstrip("/") for u in urls]
        self.tld_to_services = mapping

    def rdap_base_urls_for_tld(self, tld: str) -> List[str]:
        return self.tld_to_services.get(tld.lower(), [])


def rdap_domain_lookup(session: requests.Session, bootstrap: RdapBootstrap, domain_ascii: str) -> Dict[str, Any]:
    tld = split_tld(domain_ascii)
    bases = bootstrap.rdap_base_urls_for_tld(tld)
    if not bases:
        return {"error": f"No RDAP bootstrap entry for TLD: {tld}"}

    last_err = None
    for base in bases:
        url = f"{base}/domain/{domain_ascii}"
        try:
            r = session.get(url, timeout=20, headers={"Accept": "application/rdap+json, application/json"})
            if r.status_code == 404:
                return {"error": "RDAP: domain not found", "rdap_url": url, "status_code": 404}
            r.raise_for_status()
            data = r.json()
            data["_rdap_url"] = url
            return data
        except Exception as e:
            last_err = str(e)
            continue
    return {"error": f"RDAP lookup failed: {last_err or 'unknown'}"}


def extract_rdap_fields(rdap: Dict[str, Any]) -> Dict[str, str]:
    out: Dict[str, str] = {
        "rdap_registrar": "",
        "rdap_registrant": "",
        "rdap_registrant_org": "",
        "rdap_nameservers": "",
        "rdap_status": "",
    }
    if not rdap or "error" in rdap:
        out["rdap_status"] = rdap.get("error", "")
        return out

    # Nameservers
    nss = []
    for ns in (rdap.get("nameservers", []) or []):
        name = ns.get("ldhName") or ns.get("unicodeName") or ""
        if name:
            nss.append(name)
    out["rdap_nameservers"] = safe_join(sorted(set(nss)))

    # Status
    st = rdap.get("status") or []
    if isinstance(st, list):
        out["rdap_status"] = safe_join([str(x) for x in st])

    # Entities: registrar/registrant in roles (often redacted)
    entities = rdap.get("entities") or []
    registrar_names = []
    registrant_names = []
    registrant_orgs = []

    def vcard_get(vcard, keys):
        res = {}
        try:
            arr = vcard[1]  # ["vcard", [ ... ]]
            for entry in arr:
                if len(entry) >= 4 and entry[0] in keys:
                    res[entry[0]] = str(entry[3])
        except Exception:
            pass
        return res

    for ent in entities:
        roles = ent.get("roles") or []
        vcard = ent.get("vcardArray")
        vc = vcard_get(vcard, ["fn", "org"]) if vcard else {}
        fn = vc.get("fn", "")
        org = vc.get("org", "")

        if "registrar" in roles:
            registrar_names.append(fn or org)

        if "registrant" in roles:
            if fn:
                registrant_names.append(fn)
            if org:
                registrant_orgs.append(org)

    out["rdap_registrar"] = safe_join(sorted(set([x for x in registrar_names if x])))
    out["rdap_registrant"] = safe_join(sorted(set([x for x in registrant_names if x])))
    out["rdap_registrant_org"] = safe_join(sorted(set([x for x in registrant_orgs if x])))
    return out


# --- DNS ---------------------------------------------------------------------

def resolve_ips(domain_ascii: str) -> Tuple[List[str], List[str]]:
    a_records: List[str] = []
    aaaa_records: List[str] = []
    try:
        infos = socket.getaddrinfo(domain_ascii, None, proto=socket.IPPROTO_TCP)
        for family, _, _, _, sockaddr in infos:
            ip = sockaddr[0]
            if family == socket.AF_INET:
                a_records.append(ip)
            elif family == socket.AF_INET6:
                aaaa_records.append(ip)
    except Exception:
        pass
    return sorted(set(a_records)), sorted(set(aaaa_records))


def reverse_dns(ip: str) -> str:
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return host
    except Exception:
        return ""


# --- HTTP/HTTPS --------------------------------------------------------------

def fetch_url(session: requests.Session, url: str) -> Dict[str, Any]:
    try:
        r = session.get(url, timeout=20, allow_redirects=True)
        history = [f"{h.status_code} {h.url}" for h in r.history]
        return {
            "ok": True,
            "status_code": r.status_code,
            "final_url": r.url,
            "redirect_chain": history,
            "server": r.headers.get("Server", ""),
            "via": r.headers.get("Via", ""),
            "powered_by": r.headers.get("X-Powered-By", ""),
        }
    except Exception as e:
        return {"ok": False, "error": str(e), "status_code": "", "final_url": "", "redirect_chain": []}


# --- TLS ---------------------------------------------------------------------

def tls_cert_info(hostname_ascii: str, port: int = 443) -> Dict[str, str]:
    out = {"tls_subject": "", "tls_issuer": "", "tls_san": ""}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname_ascii, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname_ascii) as ssock:
                cert = ssock.getpeercert()

        def flatten_name(name_tuple) -> str:
            parts = []
            for rdn in name_tuple:
                for k, v in rdn:
                    parts.append(f"{k}={v}")
            return ", ".join(parts)

        out["tls_subject"] = flatten_name(cert.get("subject", ()))
        out["tls_issuer"] = flatten_name(cert.get("issuer", ()))
        san = cert.get("subjectAltName", ())
        sans = [v for (t, v) in san if str(t).lower() == "dns"]
        out["tls_san"] = safe_join(sans)
    except Exception:
        pass
    return out


# --- Provider heuristics -----------------------------------------------------

def detect_provider(nameservers: str, server_header: str, tls_issuer: str, rdns: str) -> str:
    """
    Best-effort "human" provider label based on common indicators.
    Not guaranteed to be correct.
    """
    hay = " | ".join([nameservers, server_header, tls_issuer, rdns]).lower()

    rules = [
        ("cloudflare", "Cloudflare (DNS/CDN)"),
        ("ui-dns", "IONOS (DNS)"),
        ("1and1", "IONOS (legacy)"),
        ("amazonaws", "AWS (Route53/ELB/CloudFront)"),
        ("awsglobalaccelerator", "AWS (Global Accelerator)"),
        ("azure", "Microsoft Azure"),
        ("google", "Google Cloud / Google Domains"),
        ("gcore", "Gcore"),
        ("fastly", "Fastly"),
        ("akamai", "Akamai"),
        ("stackpathdns", "StackPath"),
        ("digitalocean", "DigitalOcean"),
        ("netcup", "netcup"),
        ("hetzner", "Hetzner"),
    ]

    for needle, label in rules:
        if needle in hay:
            return label
    return ""


# --- Model -------------------------------------------------------------------

@dataclass
class DomainResult:
    input_domain: str
    domain_ascii: str
    tld: str

    provider_guess: str

    a_records: str
    aaaa_records: str
    rdns: str

    rdap_registrar: str
    rdap_registrant: str
    rdap_registrant_org: str
    rdap_nameservers: str
    rdap_status: str

    http_final_url: str
    http_status: str
    http_redirect_chain: str
    http_server: str
    http_via: str
    http_powered_by: str

    https_final_url: str
    https_status: str
    https_redirect_chain: str
    https_server: str
    https_via: str
    https_powered_by: str

    tls_subject: str
    tls_issuer: str
    tls_san: str

    scanned_at: str


# --- Main --------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description="Domain audit: RDAP + DNS + redirects + TLS. Outputs CSV + JSON.")
    ap.add_argument("--in", dest="infile", required=True, help="Input file (.txt or .json) with domains")
    ap.add_argument("--out", dest="outdir", default="out", help="Output directory")
    ap.add_argument("--user-agent", dest="ua", default="domain-audit/1.1", help="HTTP User-Agent")
    args = ap.parse_args()

    infile = Path(args.infile)
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    domains = read_domains(infile)
    if not domains:
        print("No domains found in input.", file=sys.stderr)
        return 2

    session = requests.Session()
    session.headers.update({"User-Agent": args.ua})

    bootstrap = RdapBootstrap(session)
    try:
        bootstrap.load()
    except Exception as e:
        print(f"Failed to load IANA RDAP bootstrap: {e}", file=sys.stderr)
        return 3

    results: List[DomainResult] = []
    json_rows: List[Dict[str, Any]] = []

    for d in domains:
        d_ascii = to_punycode(d)
        tld = split_tld(d_ascii)

        a, aaaa = resolve_ips(d_ascii)
        rdns_list = [reverse_dns(ip) for ip in (a[:3] + aaaa[:3])]
        rdns = safe_join([x for x in rdns_list if x])

        rdap_raw = rdap_domain_lookup(session, bootstrap, d_ascii)
        rdap_fields = extract_rdap_fields(rdap_raw)

        http = fetch_url(session, f"http://{d_ascii}")
        https = fetch_url(session, f"https://{d_ascii}")
        tls = tls_cert_info(d_ascii)

        provider_guess = detect_provider(
            nameservers=rdap_fields.get("rdap_nameservers", ""),
            server_header=safe_join([http.get("server",""), https.get("server","")]),
            tls_issuer=tls.get("tls_issuer",""),
            rdns=rdns,
        )

        scanned = now_iso()

        row = DomainResult(
            input_domain=d,
            domain_ascii=d_ascii,
            tld=tld,

            provider_guess=provider_guess,

            a_records=safe_join(a),
            aaaa_records=safe_join(aaaa),
            rdns=rdns,

            rdap_registrar=rdap_fields["rdap_registrar"],
            rdap_registrant=rdap_fields["rdap_registrant"],
            rdap_registrant_org=rdap_fields["rdap_registrant_org"],
            rdap_nameservers=rdap_fields["rdap_nameservers"],
            rdap_status=rdap_fields["rdap_status"],

            http_final_url=http.get("final_url", ""),
            http_status=str(http.get("status_code", "")),
            http_redirect_chain=safe_join(http.get("redirect_chain", [])),
            http_server=http.get("server", ""),
            http_via=http.get("via", ""),
            http_powered_by=http.get("powered_by", ""),

            https_final_url=https.get("final_url", ""),
            https_status=str(https.get("status_code", "")),
            https_redirect_chain=safe_join(https.get("redirect_chain", [])),
            https_server=https.get("server", ""),
            https_via=https.get("via", ""),
            https_powered_by=https.get("powered_by", ""),

            tls_subject=tls.get("tls_subject", ""),
            tls_issuer=tls.get("tls_issuer", ""),
            tls_san=tls.get("tls_san", ""),

            scanned_at=scanned
        )

        results.append(row)

        json_rows.append({
            "input_domain": d,
            "domain_ascii": d_ascii,
            "tld": tld,
            "provider_guess": provider_guess,
            "dns": {"a": a, "aaaa": aaaa, "reverse_dns": [x for x in rdns_list if x]},
            "rdap_raw": rdap_raw,
            "http": http,
            "https": https,
            "tls": tls,
            "scanned_at": scanned,
        })

    # CSV
    csv_path = outdir / "domains_audit.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(asdict(results[0]).keys()))
        writer.writeheader()
        for r in results:
            writer.writerow(asdict(r))

    # JSON
    json_path = outdir / "domains_audit.json"
    json_path.write_text(json.dumps(json_rows, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"Done.\nCSV:  {csv_path}\nJSON: {json_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
