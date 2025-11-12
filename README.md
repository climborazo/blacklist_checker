# 🕵️‍♂️ Blacklist Checker

A Python based tool to check domains against multiple **Blacklist** and **Threat Intelligence** providers.  
It includes an **Interactive Launcher (`run.py`)**, organized output directories, and batch automation support.

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

# Optional for Pdf/Docx export

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

## 📂 Project Structure

```
blacklist_checker/
├─ bl.py                # Main blacklist checker script
├─ run.py               # Interactive launcher
├─ input/               # Domain list files (.txt, one domain per line)
├─ report/              # Outputs grouped by input file name
├─ config/
│  └─ .env              # Environment variables and API keys
├─ logs/                # Optional log files
├─ scripts/
│  └─ run_batch.sh      # Non interactive batch execution
├─ requirements.txt
├─ .env.example
├─ .gitignore
└─ README.md
```

---

## 🌐 Supported Providers

| Provider                | API Key | Type | Notes |
|--------------------------|:--------:|------|-------|
| **Spamhaus Dbl**         | ❌ | Dns | Free Dnsbl service, suitable for moderate use |
| **Surbl**                | ❌ | Dns | Requires local resolver (avoid public Dns for bulk use) |
| **Uribl**                | ❌ | Dns | Free but limited, local resolver recommended |
| **Urlhaus**              | ❌ | Http | Public abuse.ch malware feed |
| **Google Safe Browsing** | ✅ | Http | Free tier (Google Cloud Api key required) |
| **AlienVault Otx**       | ✅ | Http | Free account required for Api key |
| **Virustotal**           | ✅ | Http | Free public Api (rate limited) |
| **Threatfox**            | ✅ | Http | Free Auth Key (requires abuse.ch account) |
| **Openphish (Community)**| ❌ | Http | Public phishing feed |

> If an Api key is missing, `bl.py` automatically skips that provider and continues.

---

## 🧰 Usage

### ▶️ Interactive Mode

```bash
python3 run.py
```

1. Choose the input file from the `input/` directory  
2. Select the desired output format: `html` (default), `json`, `csv`, `docx`, or `pdf`  
3. Choose between **Automatic Naming** (recommended) or a **Custom Filename**  
4. The output will be created under `report/<input_basename>/`

### ⚙️ Batch Mode

```bash
bash scripts/run_batch.sh
```

You can override these environment variables if needed:

```bash
FORMAT=html          # Or json / csv
PROVIDERS=default    # Or all, or a comma separated list
INPUT_DIR=input
REPORT_DIR=report
```

Each input file in `input/` will produce a corresponding subfolder under `report/`.

---

## 🔑 Environment Variables

Example `.env` file:
```bash

# Api Keys (optional)

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

- **Automatic Output Naming**: `inputname_DD_MM_YY.html`
- **Automatic Report Folders**: Each input file gets its own folder under `report/`
- **Resilient Provider Logic**: Gracefully skips unavailable or unauthenticated sources
- **Multiple Output Formats**: Html, Json, Csv, Pdf, Docx
- **Batch Mode** For automation and scheduling
- **Timezone Aware Output** (Europe / Rome default)

---

## 🧭 Troubleshooting

| Issue | Cause | Fix |
|-------|--------|-----|
| `KeyError: 'provider'` | A provider was removed from mapping but still listed in defaults | The “default” provider list now filters automatically; check your `--providers` argument |
| API 401 / quota errors | Rate limit or missing key | Verify `.env` keys and provider limits |
| Empty output | No detections or invalid domains | Check that each domain is on a separate line |

---

## 🪪 License

This project is licensed under the **Gnu Gpl Version 3** — see the [LICENSE.md](LICENSE.md) file for details.

---

## 👨‍💻 Author

Developed and maintained by **[climborazo](https://github.com/climborazo)**  
Contributions and pull requests are welcome...
