# 🕵️‍♂️ Blacklist Checker

A Python based tool to check domains against multiple **Blacklist** and **Threat Intelligence** providers.  
It features an **interactive Launcher (`run.py`)**, structured output directories, and easy batch execution.

---

## ⚙️ Requirements

- **Python 3.9+**
- (Optional) `pandoc` if you want to export **Pdf** or **Docx** reports
- Internet connection (for provider lookups)

---

## 🚀 Installation (Ubuntu / Debian)

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip
# Optional for Pdf / Docx export
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
├─ bl.py                # Main blacklist checker script
├─ run.py               # Interactive launcher
├─ input/               # Domain list files (.txt, one domain per line)
├─ report/              # Outputs grouped by input file name
├─ config/
│  └─ .env              # Environment variables and Api keys
├─ logs/                # Optional log files
├─ scripts/
│  └─ run_batch.sh      # Non interactive batch execution
├─ requirements.txt
├─ .env.example
├─ .gitignore
└─ README.md
```

---

## 🌐 Supported providers

| Provider             | API Key | Type | Notes |
|----------------------|:--------:|------|-------|
| **Spamhaus Dbl**     | ❌ | Dns | Free Dnsbl service, suitable for moderate use |
| **Surbl**            | ❌ | Dns | Requires local resolver (avoid public Dns for bulk use) |
| **Uribl**            | ❌ | Dns | Free but limited, local resolver recommended |
| **Urlhaus**          | ❌ | Http | Public abuse.ch malware feed |
| **Google Safe Browsing** | ✅ | Http | Free Tier (Google Cloud Api key required) |
| **AlienVault Otx**   | ✅ | Http | Free account required for Api key |
| **Virustotal**       | ✅ | Http | Free public Api (rate limited) |
| **Threatfox**        | ✅ | Http | Free Auth Key (requires abuse.ch account) |
| **Openphish (Community)** | ❌ | Http | Public phishing feed |

> If an Api key is missing, `bl.py` automatically skips that provider and continues.

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
FORMAT=html          # Or json / csv
PROVIDERS=default    # Or all, or a comma separated list
INPUT_DIR=input
REPORT_DIR=report
```

Each input file in `input/` will produce a corresponding subfolder under `report/`.

---

## 🔑 Environment variables

Example `.env` file:
```bash
# Api keys (optional)
GSB_API_KEY=            # Google Safe Browsing
VT_API_KEY=             # Virustotal
THREATFOX_AUTH_KEY=     # Threatfox (abuse.ch)
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
- **Supports multiple formats**: Html, Json, Csv, Pdf, Docx
- **Batch execution** for scheduled tasks or automation
- **Timezone-aware output** (Europe/Rome by default)

---

## 🧭 Troubleshooting

| Issue | Cause | Fix |
|-------|--------|-----|
| `KeyError: 'provider'` | A provider was removed from mapping but still listed in defaults | The “default” provider list now filters automatically; check your `--providers` argument |
| Api 401 / quota errors | Rate limit or missing key | Verify `.env` keys and provider limits |
| Empty output | No detections or invalid domains | Check domain list format (one per line) |

---

## 🪪 License

This project is licensed under the **GNU Gpl Version 3** — see the [LICENSE.md](LICENSE.md) file for details.

---

## 👨‍💻 Author

Developed and maintained by **[climborazo](https://github.com/climborazo)**  
Contributions and pull requests are welcome...
