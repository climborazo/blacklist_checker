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
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    
    :root {{
      --bg-primary: #ffffff;
      --bg-secondary: #f8f9fa;
      --bg-card: #ffffff;
      --text-primary: #1a1a1a;
      --text-secondary: #6c757d;
      --border-color: #dee2e6;
      --success: #10b981;
      --danger: #ef4444;
      --warning: #f59e0b;
      --info: #3b82f6;
      --shadow: 0 1px 3px rgba(0,0,0,0.12), 0 1px 2px rgba(0,0,0,0.24);
      --shadow-lg: 0 10px 25px rgba(0,0,0,0.1);
    }}
    
    body.dark-mode {{
      --bg-primary: #1a1a1a;
      --bg-secondary: #2d2d2d;
      --bg-card: #242424;
      --text-primary: #e5e5e5;
      --text-secondary: #a0a0a0;
      --border-color: #404040;
      --shadow: 0 1px 3px rgba(0,0,0,0.3), 0 1px 2px rgba(0,0,0,0.5);
      --shadow-lg: 0 10px 25px rgba(0,0,0,0.3);
    }}
    
    body {{
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', 'Oxygen', 'Ubuntu', sans-serif;
      background: var(--bg-secondary);
      color: var(--text-primary);
      line-height: 1.6;
      transition: background-color 0.3s ease, color 0.3s ease;
    }}
    
    .container {{
      max-width: 1400px;
      margin: 0 auto;
      padding: 20px;
    }}
    
    header {{
      background: var(--bg-card);
      padding: 24px;
      border-radius: 12px;
      box-shadow: var(--shadow);
      margin-bottom: 24px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 16px;
    }}
    
    h1 {{
      font-size: 28px;
      font-weight: 700;
      color: var(--text-primary);
      display: flex;
      align-items: center;
      gap: 12px;
    }}
    
    .header-actions {{
      display: flex;
      gap: 12px;
      align-items: center;
    }}
    
    .theme-toggle {{
      background: var(--bg-secondary);
      border: 1px solid var(--border-color);
      padding: 8px 16px;
      border-radius: 8px;
      cursor: pointer;
      font-size: 14px;
      color: var(--text-primary);
      transition: all 0.2s;
    }}
    
    .theme-toggle:hover {{
      transform: translateY(-1px);
      box-shadow: var(--shadow);
    }}
    
    .meta {{
      color: var(--text-secondary);
      font-size: 14px;
      margin-top: 8px;
    }}
    
    .dashboard {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
      gap: 20px;
      margin-bottom: 24px;
    }}
    
    .stat-card {{
      background: var(--bg-card);
      padding: 20px;
      border-radius: 12px;
      box-shadow: var(--shadow);
      transition: transform 0.2s, box-shadow 0.2s;
    }}
    
    .stat-card:hover {{
      transform: translateY(-2px);
      box-shadow: var(--shadow-lg);
    }}
    
    .stat-value {{
      font-size: 32px;
      font-weight: 700;
      margin: 8px 0;
    }}
    
    .stat-label {{
      color: var(--text-secondary);
      font-size: 14px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }}
    
    .stat-card.danger .stat-value {{ color: var(--danger); }}
    .stat-card.success .stat-value {{ color: var(--success); }}
    .stat-card.info .stat-value {{ color: var(--info); }}
    
    .controls {{
      background: var(--bg-card);
      padding: 20px;
      border-radius: 12px;
      box-shadow: var(--shadow);
      margin-bottom: 24px;
      display: flex;
      flex-wrap: wrap;
      gap: 12px;
      align-items: center;
    }}
    
    .search-box {{
      flex: 1;
      min-width: 250px;
      position: relative;
    }}
    
    .search-box input {{
      width: 100%;
      padding: 10px 40px 10px 16px;
      border: 1px solid var(--border-color);
      border-radius: 8px;
      font-size: 14px;
      background: var(--bg-secondary);
      color: var(--text-primary);
      transition: all 0.2s;
    }}
    
    .search-box input:focus {{
      outline: none;
      border-color: var(--info);
      box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1);
    }}
    
    .search-icon {{
      position: absolute;
      right: 12px;
      top: 50%;
      transform: translateY(-50%);
      color: var(--text-secondary);
    }}
    
    .filter-group {{
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
    }}
    
    .filter-btn {{
      padding: 8px 16px;
      border: 1px solid var(--border-color);
      background: var(--bg-secondary);
      color: var(--text-primary);
      border-radius: 8px;
      cursor: pointer;
      font-size: 14px;
      transition: all 0.2s;
    }}
    
    .filter-btn:hover {{
      background: var(--bg-card);
      transform: translateY(-1px);
    }}
    
    .filter-btn.active {{
      background: var(--info);
      color: white;
      border-color: var(--info);
    }}
    
    .table-container {{
      background: var(--bg-card);
      border-radius: 12px;
      box-shadow: var(--shadow);
      overflow: hidden;
    }}
    
    .table-wrapper {{
      overflow-x: auto;
    }}
    
    table {{
      width: 100%;
      border-collapse: collapse;
    }}
    
    thead {{
      background: var(--bg-secondary);
      position: sticky;
      top: 0;
      z-index: 10;
    }}
    
    th {{
      padding: 16px;
      text-align: left;
      font-weight: 600;
      color: var(--text-primary);
      border-bottom: 2px solid var(--border-color);
      cursor: pointer;
      user-select: none;
      white-space: nowrap;
    }}
    
    th:hover {{
      background: var(--bg-card);
    }}
    
    th.sortable::after {{
      content: '⇅';
      margin-left: 8px;
      opacity: 0.3;
    }}
    
    th.sort-asc::after {{
      content: '↑';
      opacity: 1;
    }}
    
    th.sort-desc::after {{
      content: '↓';
      opacity: 1;
    }}
    
    td {{
      padding: 16px;
      border-bottom: 1px solid var(--border-color);
    }}
    
    tbody tr {{
      transition: background-color 0.2s;
    }}
    
    tbody tr:hover {{
      background: var(--bg-secondary);
    }}
    
    .status-badge {{
      display: inline-block;
      padding: 4px 12px;
      border-radius: 12px;
      font-size: 12px;
      font-weight: 600;
      text-transform: uppercase;
    }}
    
    .status-listed {{
      background: rgba(239, 68, 68, 0.1);
      color: var(--danger);
    }}
    
    .status-clean {{
      background: rgba(16, 185, 129, 0.1);
      color: var(--success);
    }}
    
    .domain-cell {{
      font-family: 'Monaco', 'Courier New', monospace;
      font-weight: 500;
    }}
    
    .provider-cell {{
      font-weight: 600;
    }}
    
    .link-btn {{
      display: inline-block;
      padding: 6px 12px;
      background: var(--info);
      color: white;
      text-decoration: none;
      border-radius: 6px;
      font-size: 13px;
      transition: all 0.2s;
    }}
    
    .link-btn:hover {{
      background: #2563eb;
      transform: translateY(-1px);
      box-shadow: var(--shadow);
    }}
    
    .no-results {{
      text-align: center;
      padding: 60px 20px;
      color: var(--text-secondary);
    }}
    
    .no-results-icon {{
      font-size: 48px;
      margin-bottom: 16px;
      opacity: 0.5;
    }}
    
    footer {{
      margin-top: 24px;
      padding: 20px;
      background: var(--bg-card);
      border-radius: 12px;
      box-shadow: var(--shadow);
      text-align: center;
      color: var(--text-secondary);
      font-size: 14px;
    }}
    
    .export-btns {{
      display: flex;
      gap: 8px;
    }}
    
    .export-btn {{
      padding: 8px 16px;
      background: var(--bg-secondary);
      border: 1px solid var(--border-color);
      color: var(--text-primary);
      border-radius: 8px;
      cursor: pointer;
      font-size: 14px;
      transition: all 0.2s;
    }}
    
    .export-btn:hover {{
      background: var(--bg-card);
      transform: translateY(-1px);
    }}
    
    @media (max-width: 768px) {{
      .container {{ padding: 12px; }}
      header {{ flex-direction: column; align-items: flex-start; }}
      .controls {{ flex-direction: column; align-items: stretch; }}
      .filter-group {{ width: 100%; }}
      .export-btns {{ flex-direction: column; }}
      th, td {{ padding: 12px 8px; font-size: 14px; }}
    }}
    
    @media print {{
      .controls, .theme-toggle, .export-btns, .header-actions {{ display: none; }}
      body {{ background: white; color: black; }}
      .table-container {{ box-shadow: none; }}
    }}
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div>
        <h1>
          <span>🛡️</span>
          Domain Blacklist Report
        </h1>
        <div class="meta">Generated - {generated}</div>
      </div>
      <div class="header-actions">
        <div class="export-btns">
          <button class="export-btn" onclick="exportToCSV()">📥 Export CSV</button>
          <button class="export-btn" onclick="window.print()">🖨️ Print</button>
        </div>
        <button class="theme-toggle" onclick="toggleTheme()">🌓 Theme</button>
      </div>
    </header>
    
    <div class="dashboard">
      <div class="stat-card info">
        <div class="stat-label">Total Domains</div>
        <div class="stat-value">{domain_count}</div>
      </div>
      <div class="stat-card info">
        <div class="stat-label">Total Checks</div>
        <div class="stat-value">{total_checks}</div>
      </div>
      <div class="stat-card danger">
        <div class="stat-label">Listed</div>
        <div class="stat-value" id="listed-count">{listed_count}</div>
      </div>
      <div class="stat-card success">
        <div class="stat-label">Clean</div>
        <div class="stat-value" id="clean-count">{clean_count}</div>
      </div>
    </div>
    
    <div class="controls">
      <div class="search-box">
        <input type="text" id="search" placeholder="Search domains, providers, or reasons..." onkeyup="filterTable()">
        <span class="search-icon">🔍</span>
      </div>
      <div class="filter-group">
        <button class="filter-btn active" data-filter="all" onclick="setFilter('all')">All</button>
        <button class="filter-btn" data-filter="listed" onclick="setFilter('listed')">Listed Only</button>
        <button class="filter-btn" data-filter="clean" onclick="setFilter('clean')">Clean Only</button>
      </div>
    </div>
    
    <div class="table-container">
      <div class="table-wrapper">
        <table id="data-table">
          <thead>
            <tr>
              <th class="sortable" onclick="sortTable(0)">Domain</th>
              <th class="sortable" onclick="sortTable(1)">Provider</th>
              <th class="sortable" onclick="sortTable(2)">Status</th>
              <th class="sortable" onclick="sortTable(3)">Reason</th>
              <th>Verify</th>
            </tr>
          </thead>
          <tbody id="table-body">
            {rows}
          </tbody>
        </table>
      </div>
      <div id="no-results" class="no-results" style="display: none;">
        <div class="no-results-icon">🔍</div>
        <div>No results found</div>
      </div>
    </div>
    
    <footer>
      <div><strong>Providers - </strong> {providers}</div>
      <div style="margin-top: 8px; opacity: 0.7;">
        Report generated by <strong>Domain Blacklist Checker</strong> • Data is accurate as of generation time
      </div>
    </footer>
  </div>
  
  <script>
    const allRows = {rows_json};
    let currentFilter = 'all';
    let sortColumn = -1;
    let sortAsc = true;
    
    // Theme toggle
    function toggleTheme() {{
      document.body.classList.toggle('dark-mode');
      localStorage.setItem('theme', document.body.classList.contains('dark-mode') ? 'dark' : 'light');
    }}
    
    // Load saved theme
    if (localStorage.getItem('theme') === 'dark') {{
      document.body.classList.add('dark-mode');
    }}
    
    // Filter functions
    function setFilter(filter) {{
      currentFilter = filter;
      document.querySelectorAll('.filter-btn').forEach(btn => {{
        btn.classList.toggle('active', btn.dataset.filter === filter);
      }});
      filterTable();
    }}
    
    function filterTable() {{
      const search = document.getElementById('search').value.toLowerCase();
      const tbody = document.getElementById('table-body');
      const noResults = document.getElementById('no-results');
      let visibleCount = 0;
      let listedVisible = 0;
      let cleanVisible = 0;
      
      tbody.querySelectorAll('tr').forEach(row => {{
        const isListed = row.dataset.listed === 'true';
        const text = row.textContent.toLowerCase();
        
        let show = true;
        
        if (currentFilter === 'listed' && !isListed) show = false;
        if (currentFilter === 'clean' && isListed) show = false;
        if (search && !text.includes(search)) show = false;
        
        row.style.display = show ? '' : 'none';
        if (show) {{
          visibleCount++;
          if (isListed) listedVisible++;
          else cleanVisible++;
        }}
      }});
      
      noResults.style.display = visibleCount === 0 ? 'block' : 'none';
      tbody.style.display = visibleCount === 0 ? 'none' : '';
    }}
    
    // Sort table
    function sortTable(col) {{
      const tbody = document.getElementById('table-body');
      const rows = Array.from(tbody.querySelectorAll('tr'));
      
      if (sortColumn === col) {{
        sortAsc = !sortAsc;
      }} else {{
        sortColumn = col;
        sortAsc = true;
      }}
      
      rows.sort((a, b) => {{
        let aVal = a.cells[col].textContent.trim();
        let bVal = b.cells[col].textContent.trim();
        
        if (col === 2) {{ // Status column
          aVal = a.dataset.listed === 'true' ? '1' : '0';
          bVal = b.dataset.listed === 'true' ? '1' : '0';
        }}
        
        return sortAsc ? aVal.localeCompare(bVal) : bVal.localeCompare(aVal);
      }});
      
      rows.forEach(row => tbody.appendChild(row));
      
      document.querySelectorAll('th').forEach((th, i) => {{
        th.classList.remove('sort-asc', 'sort-desc');
        if (i === col) {{
          th.classList.add(sortAsc ? 'sort-asc' : 'sort-desc');
        }}
      }});
    }}
    
    // Export to CSV
    function exportToCSV() {{
      const rows = [['Domain', 'Provider', 'Status', 'Reason', 'Verify Link']];
      
      document.querySelectorAll('#table-body tr').forEach(row => {{
        if (row.style.display !== 'none') {{
          const cells = row.querySelectorAll('td');
          rows.push([
            cells[0].textContent,
            cells[1].textContent,
            cells[2].textContent,
            cells[3].textContent,
            cells[4].querySelector('a').href
          ]);
        }}
      }});
      
      const csv = rows.map(r => r.map(c => `"${{c}}"`).join(',')).join('\\n');
      const blob = new Blob([csv], {{ type: 'text/csv' }});
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'blacklist-report-' + new Date().toISOString().split('T')[0] + '.csv';
      a.click();
      window.URL.revokeObjectURL(url);
    }}
  </script>
</body>
</html>
"""


def render_html(hits: List[Hit], providers_used: List[str]) -> str:
    tz = zoneinfo.ZoneInfo("Europe/Rome")
    now_local = dt.datetime.now(tz)
    
    # Calculate stats
    total_checks = len(hits)
    listed_count = sum(1 for h in hits if h.listed)
    clean_count = total_checks - listed_count
    domain_count = len(set(h.domain for h in hits))
    
    rows = []
    rows_data = []
    for h in hits:
        status_class = "status-listed" if h.listed else "status-clean"
        status_text = "Listed" if h.listed else "Clean"
        
        rows.append(
            f"<tr data-listed='{str(h.listed).lower()}'>"
            f"<td class='domain-cell'>{html.escape(dcase(h.domain))}</td>"
            f"<td class='provider-cell'>{html.escape(tcase(h.provider))}</td>"
            f"<td><span class='status-badge {status_class}'>{status_text}</span></td>"
            f"<td>{html.escape(tcase(h.reason))}</td>"
            f"<td><a href='{html.escape(h.link)}' target='_blank' rel='noopener' class='link-btn'>View Details</a></td>"
            f"</tr>"
        )
        
        rows_data.append({
            'domain': dcase(h.domain),
            'provider': tcase(h.provider),
            'listed': h.listed,
            'reason': tcase(h.reason),
            'link': h.link
        })
    
    formatted_providers = ", ".join([p.replace("_", " ").title() for p in providers_used])
    
    return HTML_TEMPLATE.format(
        generated=html.escape(now_local.strftime("%Y-%m-%d %H:%M (Europe / Rome)")),
        providers=formatted_providers,
        domain_count=domain_count,
        total_checks=total_checks,
        listed_count=listed_count,
        clean_count=clean_count,
        rows="\n".join(rows),
        rows_json=json.dumps(rows_data)
    )

def save_csv(path: str, hits: List[Hit]):
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Domain", "Provider", "Status", "Reason", "Verify_Link"])
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
    generated_line = f"Generated - {now_local.strftime('%Y-%m-%d %H:%M (Europe / Rome)')} | Providers ({', '.join([p.replace('_',' ').title() for p in provider_keys])}) | Domains Checked: {len(set([h.domain for h in hits]))}"
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