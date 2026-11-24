#!/usr/bin/env bash
# Exporta INFORME.org a PDF usando Emacs/Org + pdflatex.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "==> Org -> LaTeX"
emacs -Q --batch INFORME.org \
  --eval '(progn (require (quote ox-latex)) (org-latex-export-to-latex))'

echo "==> LaTeX -> PDF (dos pasadas para referencias)"
for i in 1 2; do
  pdflatex -interaction=nonstopmode -halt-on-error INFORME.tex \
    > "/tmp/opencode/informe_pdflatex_${i}.log" 2>&1 || {
      tail -60 "/tmp/opencode/informe_pdflatex_${i}.log" >&2
      exit 1
    }
done

echo "==> Listo: INFORME.pdf"
pdfinfo INFORME.pdf | grep -E '^(Title|Pages|Page size)' || true
