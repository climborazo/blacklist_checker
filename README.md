# 🕵️‍♂️ Blacklist Checker

A Python-based tool to check domains against multiple **blacklist** and **threat intelligence** providers.  
It features an **interactive launcher (`run.py`)**, structured output directories, and easy batch execution.

---

## ⚙️ Requirements

- **Python 3.9+**
- (Optional) `pandoc` if you want to export **PDF** or **DOCX** reports
- Internet connection (for provider lookups)

---

## 🚀 Installation (Ubuntu/Debian)

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip
# Optional for PDF/DOCX export
sudo apt install -y pandoc

git clone https://github.com/climborazo/blacklist_checker.git
cd blacklist_checker

python3 -m venv .venv
. .venv/bin/activate
pip install -U pip
pip install -r requirements.txt

cp .env.example config/.env
set -a; source config/.env; set +a
```

---

## 📂 Project structure

```
blacklist_checker/
├─ bl.py                # main blacklist checker script
├─ run.py               # interactive launcher
├─ input/               # domain list files (.txt, one domain per line)
├─ report/              # outputs grouped by input file name
├─ config/
│  └─ .env              # environment variables and API keys
├─ logs/                # optional log files
├─ scripts/
│  └─ run_batch.sh      # non-interactive batch execution
├─ requirements.txt
├─ .env.example
├─ .gitignore
└─ README.md
```

---

## 🌐 Supported providers

| Provider             | API Key | Type | Notes |
|----------------------|:--------:|------|-------|
| **Spamhaus DBL**     | ❌ | DNS | Free DNSBL service, suitable for moderate use |
| **SURBL**            | ❌ | DNS | Requires local resolver (avoid public DNS for bulk use) |
| **URIBL**            | ❌ | DNS | Free but limited; local resolver recommended |
| **URLhaus**          | ❌ | HTTP | Public abuse.ch malware feed |
| **Google Safe Browsing** | ✅ | HTTP | Free-tier (Google Cloud API key required) |
| **AlienVault OTX**   | ✅ | HTTP | Free account required for API key |
| **VirusTotal**       | ✅ | HTTP | Free public API (rate limited) |
| **ThreatFox**        | ✅ | HTTP | Free Auth-Key (requires abuse.ch account) |
| **OpenPhish (Community)** | ❌ | HTTP | Public phishing feed |

> If an API key is missing, `bl.py` automatically skips that provider and continues.

---

## 🧰 Usage

### ▶️ Interactive mode

```bash
python3 run.py
```
1. Choose the input file from the `input/` directory  
2. Select the desired output format: `html` (default), `json`, `csv`, `docx`, or `pdf`  
3. Choose between **automatic naming** (recommended) or a **custom filename**  
4. The output will be created under `report/<input_basename>/`

### ⚙️ Batch mode

```bash
bash scripts/run_batch.sh
```

Environment variables you can override:
```bash
FORMAT=html          # or json/csv
PROVIDERS=default    # or all, or a comma-separated list
INPUT_DIR=input
REPORT_DIR=report
```

Each input file in `input/` will produce a corresponding subfolder under `report/`.

---

## 🔑 Environment variables

Example `.env` file:
```bash
# API keys (optional)
GSB_API_KEY=            # Google Safe Browsing
VT_API_KEY=             # VirusTotal
THREATFOX_AUTH_KEY=     # ThreatFox (abuse.ch)
OPENPHISH_FEED_PATH=./config/openphish.txt
```

Load the environment before running:
```bash
set -a; source config/.env; set +a
```

---

## 🧩 Features

- **Automatic output naming**: `inputname_DD_MM_YY.html`
- **Automatic report folders**: each input file gets its own subfolder under `report/`
- **Resilient provider logic**: gracefully skips unavailable or unauthenticated sources
- **Supports multiple formats**: HTML, JSON, CSV, PDF, DOCX
- **Batch execution** for scheduled tasks or automation
- **Timezone-aware output** (Europe/Rome by default)

---

## 🧭 Troubleshooting

| Issue | Cause | Fix |
|-------|--------|-----|
| `KeyError: 'provider'` | A provider was removed from mapping but still listed in defaults | The “default” provider list now filters automatically; check your `--providers` argument |
| API 401 / quota errors | Rate limit or missing key | Verify `.env` keys and provider limits |
| Empty output | No detections or invalid domains | Check domain list format (one per line) |

---

## 🪪 License

This project is licensed under the **GNU GPL v3** — see the [LICENSE.md](LICENSE.md) file for details.

---

## 👨‍💻 Author

Developed and maintained by **[climborazo](https://github.com/climborazo)**  
Contributions and pull requests are welcome!
