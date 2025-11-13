#!/usr/bin/env bash
set -euo pipefail
FORMAT=${FORMAT:-html}
PROVIDERS=${PROVIDERS:-default}
INPUT_DIR=${INPUT_DIR:-input}
REPORT_DIR=${REPORT_DIR:-report}

if [ ! -d "$INPUT_DIR" ]; then
echo "Input directory non trovata: $INPUT_DIR" >&2
exit 1
fi

for f in "$INPUT_DIR"/*.txt; do
  [ -e "$f" ] || continue
  base=$(basename "$f")
  name="${base%.*}"
  outdir="$REPORT_DIR/$name"
  mkdir -p "$outdir"
  echo "[*] Elaboro $f -> $outdir (format=$FORMAT, providers=$PROVIDERS)"
  (cd "$outdir" && python3 ../bl.py --input "../../$f" --format "$FORMAT" --providers "$PROVIDERS")
done
