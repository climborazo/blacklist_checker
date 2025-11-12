#!/usr/bin/env python3

import argparse
import csv
import datetime as dt
import html
import json
import os
import re
import shutil
import subprocess
import sys
import zoneinfo
from dataclasses import dataclass, field
from typing import Dict, List, Optional

try:
    import dns.resolver
except Exception:
    dns = None

try:
    import requests
except Exception:
    requests = None


import time
import urllib.request as _urllib
from pathlib import Path
import urllib.parse

def update_openphish_feed_if_needed(feed_path: str, force: bool = False, max_age_hours: int = 24):
    try:
        fp = Path(feed_path)
        if not fp.parent.exists():
            try:
                fp.parent.mkdir(parents=True, exist_ok=True)
            except Exception:
                pass

        need_download = force or (not fp.exists())
        if fp.exists() and not need_download:
            mtime = fp.stat().st_mtime
            age_hours = (time.time() - mtime) / 3600.0
            if age_hours > max_age_hours:
                need_download = True

        if not need_download:
            return True, "Feed Present And Fresh"

        url = "https://openphish.com/feed.txt"
        try:
            if requests is not None:
                resp = requests.get(url, timeout=20)
                resp.raise_for_status()
                content = resp.text
            else:
                with _urllib.urlopen(url, timeout=20) as r:
                    content = r.read().decode("utf-8", errors="replace")
            tmp = str(fp) + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                fh.write(content)
            Path(tmp).replace(fp)
            return True, "Downloaded"
        except Exception as e:
            return False, f"Download failed: {e}"
    except Exception as e:
        return False, f"Error: {e}"

def tcase(s: str) -> str:
    return s.title() if isinstance(s, str) else s

def dcase(s: str) -> str:
    return s.lower() if isinstance(s, str) else s


def read_domains_from_file(path: str) -> List[str]:
    items: List[str] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith("#"):
                continue

            s = re.sub(r"^https?://", "", s, flags=re.I)
            s = s.split("/")[0]
            items.append(s.lower())
    return sorted(set(items))


def _need(module_name: str, module_obj):
    if module_obj is None:
        print(f"[!] {tcase('Missing Dependency')}: {tcase(module_name)}. {tcase('Install It First.')}", file=sys.stderr)
        return False
    return True

@dataclass
class Hit:
    domain: str  
    provider: str
    listed: bool
    reason: str = ""
    link: str = ""
    raw: dict = field(default_factory=dict)

    def to_row(self) -> List[str]:
        return [dcase(self.domain), tcase(self.provider), ("Listed" if self.listed else "Not Listed"), tcase(self.reason), self.link]

def query_dns_a(name: str) -> List[str]:
    if not _need("dnspython", dns):
        return []
    try:
        answers = dns.resolver.resolve(name, "A")
        return [a.to_text() for a in answers]
    except Exception:
        return []

def check_spamhaus_dbl(domain: str) -> Hit:
    zone = "dbl.spamhaus.org"
    addrs = query_dns_a(f"{domain}.{zone}")
    listed = bool(addrs)
    reason = "Listed" if listed else "Not Listed"
    link = f"https://check.spamhaus.org/listed/?searchterm={html.escape(domain)}"
    return Hit(domain, "Spamhaus Dbl", listed, reason, link)

def check_surbl(domain: str) -> Hit:
    addrs = query_dns_a(f"{domain}.multi.surbl.org")
    listed = bool(addrs)
    reason = "Listed" if listed else "Not Listed"
    link = f"https://www.surbl.org/surbl-analysis?domain={html.escape(domain)}"
    return Hit(domain, "Surbl", listed, reason, link)

def check_uribl(domain: str) -> Hit:
    addrs = query_dns_a(f"{domain}.multi.uribl.com")
    listed = bool(addrs)
    reason = "Listed" if listed else "Not Listed"
    link = f"https://uribl.com/"
    return Hit(domain, "Uribl", listed, reason, link)

def check_urlhaus(domain: str) -> Hit:
    if not _need("requests", requests):
        return Hit(domain, "Urlhaus", False, "Requests Not Installed", "", {})
    try:
        resp = requests.post("https://urlhaus-api.abuse.ch/v1/host/", data={"host": domain}, timeout=20)
        data = resp.json()
    except Exception as e:
        return Hit(domain, "Urlhaus", False, f"Api Error: {e}", "", {})
    listed = data.get("query_status") == "ok" and int(data.get("url_count", 0)) > 0
    reason = "Malicious Urls Present" if listed else "No Urls Reported"
    link = f"https://urlhaus.abuse.ch/host/{html.escape(domain)}/"
    return Hit(domain, "Urlhaus", listed, reason, link)

def check_google_safe_browsing(domain: str) -> Hit:
    if not _need("requests", requests):
        return Hit(domain, "Gsb", False, "Requests Not Installed", "", {})
    api_key = os.environ.get("GSB_API_KEY")
    if not api_key:
        return Hit(domain, "Gsb", False, "Gsb Api Key Not Set", "", {})
    url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    body = {
        "client": {"clientId": "cti-bl-checker", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": f"http://{domain}/"}, {"url": f"https://{domain}/"}],
        },
    }
    try:
        resp = requests.post(url, json=body, timeout=20)
        data = resp.json()
    except Exception as e:
        return Hit(domain, "Gsb", False, f"Api Error: {e}", "", {})
    matches = data.get("matches", [])
    listed = len(matches) > 0
    reason = "Detected" if listed else "Not Listed"
    link = f"https://transparencyreport.google.com/safe-browsing/search?url={html.escape(domain)}"
    return Hit(domain, "Gsb", listed, reason, link)

def check_otx(domain: str) -> Hit:
    if not _need("requests", requests):
        return Hit(domain, "Otx", False, "Requests Not Installed", "", {})
    try:
        resp = requests.get(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general", timeout=20)
        data = resp.json()
    except Exception as e:
        return Hit(domain, "Otx", False, f"Api Error: {e}", "", {})
    pulses = data.get("pulse_info", {}).get("count", 0)
    listed = pulses > 0
    reason = "Referenced In Pulses" if listed else "No Pulses"
    link = f"https://otx.alienvault.com/indicator/domain/{html.escape(domain)}"
    return Hit(domain, "Otx", listed, reason, link)

def check_threatfox(domain: str) -> Hit:
    if not _need("requests", requests):
        return Hit(domain, "ThreatFox", False, "Requests Not Installed", "", {})
    auth = os.environ.get("THREATFOX_AUTH_KEY")
    if not auth:
        return Hit(domain, "ThreatFox", False, "Auth Key Not Set", "", {})
    try:
        url = "https://threatfox-api.abuse.ch/api/v1/"
        payload = {"query": "search_ioc", "search": "domain", "term": domain}
        headers = {"Content-Type": "application/json", "API-KEY": auth}
        resp = requests.post(url, headers=headers, json=payload, timeout=30)
        data = resp.json()
        iocs = data.get("data") or []
        listed = len(iocs) > 0
        reason = "IOCs Found" if listed else "No IOCs"
        link = "https://threatfox.abuse.ch/"
        return Hit(domain, "ThreatFox", listed, reason, link, {"count": len(iocs)})
    except Exception as e:
        return Hit(domain, "ThreatFox", False, f"Api Error: {e}", "", {})

def check_virustotal(domain: str) -> Hit:
    if not _need("requests", requests):
        return Hit(domain, "Virustotal", False, "Requests Not Installed", "", {})
    api_key = os.environ.get("VT_API_KEY")
    if not api_key:
        return Hit(domain, "Virustotal", False, "Vt Api Key Not Set", "", {})
    try:
        resp = requests.get(f"https://www.virustotal.com/api/v3/domains/{domain}", headers={"x-apikey": api_key}, timeout=20)
        data = resp.json()
    except Exception as e:
        return Hit(domain, "Virustotal", False, f"Api Error: {e}", "", {})
    stats = (data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})) or {}
    listed = int(stats.get("malicious", 0)) + int(stats.get("suspicious", 0)) > 0
    reason = "Malicious" if listed else "No Detections"
    link = f"https://www.virustotal.com/gui/domain/{html.escape(domain)}"
    return Hit(domain, "Virustotal", listed, reason, link)

AVAILABLE_PROVIDERS = {
    "spamhaus_dbl": check_spamhaus_dbl,
    "surbl": check_surbl,
    "urlhaus": check_urlhaus,
    "gsb": check_google_safe_browsing,
    "otx": check_otx,
    "virustotal": check_virustotal,
    "uribl": check_uribl,
    "threatfox": check_threatfox,
    
}

DEFAULT_PROVIDER_ORDER = ["spamhaus_dbl", "surbl", "urlhaus", "gsb", "otx", "virustotal", "uribl", "threatfox"]


HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Domain Blacklist Report</title>
  <style>
    body {{ font-family: 'Century Gothic', 'Gill Sans', 'Helvetica Neue', sans-serif; margin: 24px; }}
    h1 {{ margin-bottom: 0; }}
    .meta {{ color: #555; margin-top: 4px; }}
    table {{ border-collapse: collapse; width: 100%; margin-top: 20px; }}
    th, td {{ border: 1px solid #ddd; padding: 8px; vertical-align: top; }}
    th {{ background: #f4f4f4; text-align: left; }}
    tr.hit {{ background: #fff7f7; }}
    tr.hit a {{ color: #b00020; }}
    tr.hit td {{ color: #b00020; font-weight: 600; }}
    tr.ok {{ background: #f7fff7; }}
    .nowrap {{ white-space: nowrap; }}
    .provider {{ font-weight: 600; }}
  </style>
</head>
<body>
  <h1>Domain Blacklist Report</h1>
  <div class="meta">Generated: {generated} | Providers ({providers}) | Domains Checked: {domain_count}</div>
  <table>
    <thead>
      <tr>
        <th>Domain</th>
        <th>Provider</th>
        <th>Status</th>
        <th>Reason</th>
        <th>Verify</th>
      </tr>
    </thead>
    <tbody>
      {rows}
    </tbody>
  </table>
</body>
</html>
"""


def render_html(hits: List[Hit], providers_used: List[str]) -> str:
    tz = zoneinfo.ZoneInfo("Europe/Rome")
    now_local = dt.datetime.now(tz)
    rows = []
    for h in hits:
        cls = "hit" if h.listed else "ok"
        row_style = " style='color:#b00020;font-weight:600'" if h.listed else ""
        link_style = " style='color:inherit'" if h.listed else ""
        rows.append(
            f"<tr class='{cls}'{row_style}><td>{html.escape(dcase(h.domain))}</td>"
            f"<td class='provider'>{html.escape(tcase(h.provider))}</td>"
            f"<td class='nowrap'>{'Listed' if h.listed else 'Not Listed'}</td>"
            f"<td>{html.escape(tcase(h.reason))}</td>"
            f"<td><a href='{html.escape(h.link)}' target='_blank' rel='noopener'{link_style}>Link</a></td></tr>"
        )
    formatted_providers = ", ".join([p.replace("_", " ").title() for p in providers_used])
    return HTML_TEMPLATE.format(
        generated=html.escape(now_local.strftime("%Y-%m-%d %H:%M (Europe / Rome)")),
        providers=formatted_providers,
        domain_count=len({h.domain for h in hits}),
        rows="\n".join(rows),
    )

def save_csv(path: str, hits: List[Hit]):
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Domain", "Provider", "Status", "Reason", "Verify_Link"])  # header Title Case
        for h in hits:
            writer.writerow(h.to_row())

def save_json(path: str, hits: List[Hit]):

    with open(path, "w", encoding="utf-8") as f:
        payload = [
            {
                "domain": dcase(h.domain),
                "provider": tcase(h.provider),
                "status": "Listed" if h.listed else "Not Listed",
                "reason": tcase(h.reason),
                "link": h.link,
                "raw": h.raw,
            }
            for h in hits
        ]
        json.dump(payload, f, ensure_ascii=False, indent=2)

def save_html(path: str, hits: List[Hit], providers_used: List[str]):
    with open(path, "w", encoding="utf-8") as f:
        f.write(render_html(hits, providers_used))

def parse_args():
    p = argparse.ArgumentParser(description="Check Domains Against Multiple Blacklists (Title Case / Domains Lowercase)")
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--input", help="Path To File With Domains (One Per Line)")
    src.add_argument("--domains", help="Comma-Separated List Of Domains")
    p.add_argument("--providers", default="default", help="Comma-Separated Providers Or 'All'")
    p.add_argument("--format", default="html", choices=["html", "csv", "json"])
    p.add_argument("--out", default="report.html")
    p.add_argument("--also-csv")
    p.add_argument("--also-json")
    p.add_argument("--pdf")
    p.add_argument("--docx")
    return p.parse_args()

def main():
    args = parse_args()
    try:
        tz = zoneinfo.ZoneInfo('Europe/Rome')
    except Exception:
        tz = None
    now = dt.datetime.now(tz) if tz else dt.datetime.now()
    date_tag = now.strftime('%d_%m_%y')
    def _dated(name: str, default_ext: str) -> str:
        base, ext = os.path.splitext(name)
        if not ext:
            ext = default_ext
        return f"{base}_{date_tag}{ext}"
    _out_provided = args.out and args.out != 'report.html'
    if not _out_provided and getattr(args, 'input', None):
        infile = os.path.basename(args.input)
        base_in, _ = os.path.splitext(infile)
        args.out = f"{base_in}.{args.format}"
    args.out = _dated(args.out, f".{args.format}")
    print(f"Output File Resolved To: {args.out}")
    if getattr(args, 'also_csv', None):
        args.also_csv = _dated(args.also_csv, '.csv')
        print(f"Also Csv Resolved To: {args.also_csv}")
    if getattr(args, 'also_json', None):
        args.also_json = _dated(args.also_json, '.json')
        print(f"Also Json Resolved To: {args.also_json}")
    if getattr(args, 'pdf', None):
        args.pdf = _dated(args.pdf, '.pdf')
        print(f"Pdf Resolved To: {args.pdf}")
    if getattr(args, 'docx', None):
        args.docx = _dated(args.docx, '.docx')
        print(f"Docx Resolved To: {args.docx}")

    try:
        default_feed = os.environ.get('OPENPHISH_FEED_PATH', '/home/oo/Venv/Bl/openphish.txt')
        ok, msg = update_openphish_feed_if_needed(default_feed)
        if ok:
            os.environ['OPENPHISH_FEED_PATH'] = default_feed
        else:
            pass
    except Exception:
        pass

    if args.input:
        domains = read_domains_from_file(args.input)
    else:
        domains = sorted(set([d.strip().lower() for d in args.domains.split(",") if d.strip()]))

    if not domains:
        print(tcase("no domains provided."))
        sys.exit(1)

    if args.providers == "all":
        provider_keys = list(AVAILABLE_PROVIDERS.keys())
    elif args.providers == "default":
        provider_keys = [p for p in DEFAULT_PROVIDER_ORDER if p in AVAILABLE_PROVIDERS]
    else:
        provider_keys = [p.strip() for p in args.providers.split(",") if p.strip() in AVAILABLE_PROVIDERS]
        if not provider_keys:
            print(tcase("no valid providers selected. aborting."))
            sys.exit(1)
    print()
    print(f"Providers ({', '.join([p.replace('_', ' ').title() for p in provider_keys])})")
    print(f"Domains ({', '.join([dcase(d) for d in domains])})")

    hits: List[Hit] = []
    for d in domains:
        print()
        for pk in provider_keys:
            h = AVAILABLE_PROVIDERS[pk](d)
            hits.append(h)
            line = f"- {dcase(d)} @ {tcase(h.provider)}: {'Listed' if h.listed else 'Not Listed'} — {tcase(h.reason)}"
            if h.listed:
                RED, RESET = "\033[31m", "\033[0m"
                try:
                    if sys.stdout.isatty():
                        print(f"{RED}{line}{RESET}")
                    else:
                        print(line)
                except Exception:
                    print(line)
            else:
                print(line)  

    if args.format == "html":
        save_html(args.out, hits, provider_keys)
    elif args.format == "csv":
        save_csv(args.out, hits)
    else:
        save_json(args.out, hits)

    tz = zoneinfo.ZoneInfo("Europe/Rome")
    now_local = dt.datetime.now(tz)
    print()
    generated_line = f"Generated: {now_local.strftime('%Y-%m-%d %H:%M (Europe / Rome)')} | Providers ({', '.join([p.replace('_',' ').title() for p in provider_keys])}) | Domains Checked: {len(set([h.domain for h in hits]))}"
    print(generated_line)

    print(f"{tcase(args.format)} {tcase('Written To:')} {args.out}")
    print()
    if args.also_csv:
        save_csv(args.also_csv, hits)
        print(f"Csv {tcase('Written To')} {args.also_csv}")
    if args.also_json:
        save_json(args.also_json, hits)
        print(f"Json {tcase('Written To')} {args.also_json}")

    if args.pdf or args.docx:
        html_path = args.out if args.format == "html" else (args.out + ".html")
        if args.format != "html":
            save_html(html_path, hits, provider_keys)
        pandoc = shutil.which("pandoc")
        if pandoc:
            if args.pdf:
                try:
                    subprocess.run([pandoc, html_path, "-o", args.pdf], check=True)
                    print(f"Pdf {tcase('exported')}: {args.pdf}")
                except subprocess.CalledProcessError:
                    print(tcase("Pandoc Pdf Export Failed"), file=sys.stderr)
            if args.docx:
                try:
                    subprocess.run([pandoc, html_path, "-o", args.docx], check=True)
                    print(f"[+] Docx {tcase('exported')}: {args.docx}")
                except subprocess.CalledProcessError:
                    print(tcase("pandoc docx export failed"), file=sys.stderr)
        else:
            print(tcase("Pandoc Not Found... Skipping Pdf / Docx Export..."))

if __name__ == "__main__":
    main()
