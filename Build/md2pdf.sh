#!/bin/bash
# Script based on https://learnbyexample.github.io/tutorial/ebook-generation/customizing-pandoc/
SCRIPT=$(readlink -f "$0")
SCRIPTPATH=$(dirname "$SCRIPT")

pandoc "$tfl" \
    -f gfm \
    --toc \
    --listings \
    --include-in-header ${SCRIPTPATH}/Build/chapter_break.tex \
    --include-in-header ${SCRIPTPATH}/Build/inline_code.tex \
    --include-in-header ${SCRIPTPATH}/Build/bullet_style.tex \
    --include-in-header ${SCRIPTPATH}/Build/pdf_properties.tex \
    --include-in-header ${SCRIPTPATH}/Build/listings-setup.tex \
    --highlight-style ${SCRIPTPATH}/Build/pygments.theme \
    -V toc-title='Table of contents' \
    -V linkcolor:blue \
    -V geometry:a4paper \
    -V geometry:margin=2cm \
    -V mainfont="DejaVu Serif" \
    -V monofont="DejaVu Sans Mono" \
    --pdf-engine=xelatex \
    -o temp.tex

fn="${2%.*}"

perl -0777 -pe 's/begin\{document\}\n\n\K(.*?^\}$)(.+?)\n/$2\n\\thispagestyle{empty}\n\n$1\n/ms' temp.tex > ${fn}.tex

xelatex ${SCRIPTPATH}/${fn}.tex &> /dev/null
xelatex ${SCRIPTPATH}/${fn}.tex &> /dev/null

rm temp.tex "$fn".{tex,toc,aux,log}


