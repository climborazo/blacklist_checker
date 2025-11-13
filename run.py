#!/usr/bin/env python3
import os
import sys
import subprocess
from pathlib import Path

INPUT_DIR = Path.cwd() / "input"
REPORT_DIR = Path.cwd() / "report"
BL_SCRIPT = Path.cwd() / "bl.py"

def ask(msg, default=None):
    if default is None:
        return input(msg + ": ").strip()
    else:
        s = input(f"{msg} [{default}]: ").strip()
        return s or default

def pick_input():
    files = []
    if INPUT_DIR.exists() and INPUT_DIR.is_dir():
        files = [p for p in INPUT_DIR.iterdir() if p.is_file()]
        files.sort(key=lambda p: p.name.lower())
    print("\nSelect Input File...")
    print()
    if files:
        for i, p in enumerate(files, 1):
            print(f"{i}) {p.name}")
        print("0) Select Path")
        print()
        while True:
            choice = ask("Choose", "1")
            if choice.isdigit():
                idx = int(choice)
                if idx == 0:
                    manual = ask("File Path (Es. /path/domains.txt)")
                    return Path(manual)
                if 1 <= idx <= len(files):
                    return files[idx-1]
            print("Invalid choice...")
    else:
        print(f"File Missing In: {INPUT_DIR}")
        manual = ask("File Path (Ex. /path/domains.txt)")
        return Path(manual)

def pick_format():
    print("\nChoose Output Format")
    print()
    options = ["html", "json", "csv", "docx", "pdf"]
    for i, o in enumerate(options, 1):
        print(f"{i}) {o}" + (" (Default)" if o == "html" else ""))
    mapping = {"1":"html","2":"json","3":"csv","4":"docx","5":"pdf"}
    print()
    choice = ask("Choice", "1")
    return mapping.get(choice, "html")

def pick_naming(base_name, chosen_format):
    print("\nOutput File Name")
    print()
    print("1) Generate Automatically (Use Script Logic With Date Suffix) [Default]")
    print("2) Specify A Custom Name")
    print()
    choice = ask("Choice", "1")
    if choice == "2":
        custom = ask("Enter The Desired Name (With Or Without Extension). Examples: report, report.html, out.csv")
        return ("custom", custom)
    return ("auto", base_name)

def main():
    if not BL_SCRIPT.exists():
        print(f"bl.py Not Found In: {BL_SCRIPT}")
        sys.exit(1)

    infile = pick_input()
    if not infile.exists():
        print(f"File Not Found: {infile}")
        sys.exit(1)
    base_in = infile.stem

    fmt = pick_format()
    mode, val = pick_naming(base_in, fmt)

    dest_dir = REPORT_DIR / base_in
    dest_dir.mkdir(parents=True, exist_ok=True)

    cmd = [sys.executable, str(BL_SCRIPT), "--input", str(infile)]
    if fmt in ("html","json","csv"):
        cmd += ["--format", fmt]
        if mode == "custom":
            out_name = val if val.endswith(f".{fmt}") else f"{val}.{fmt}"
            out_path = dest_dir / out_name
            cmd += ["--out", str(out_path)]
        else:
            os.chdir(dest_dir)
    elif fmt == "docx":
        cmd += ["--format", "html"]
        docx_name = val if mode == "custom" else f"{base_in}.docx"
        cmd += ["--docx", str(dest_dir / docx_name)]
    elif fmt == "pdf":
        cmd += ["--format", "html"]
        pdf_name = val if mode == "custom" else f"{base_in}.pdf"
        cmd += ["--pdf", str(dest_dir / pdf_name)]
    else:
        print("Format Not Supported...")
        sys.exit(1)

    print("\nExecution")
    print()
    print("Command:", " ".join(f'\"{c}\"' if " " in c else c for c in cmd))
    print()
    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        print(f"\nExecution Failed With Code {e.returncode}")
        sys.exit(e.returncode)

if __name__ == "__main__":
    main()
