#!/bin/bash
# Script based on https://learnbyexample.github.io/tutorial/ebook-generation/customizing-pandoc/

Help()
{
   # Display Help
   echo "Generate guide PDF from a master MarkDown file."
   echo
   echo "Syntax: md2pdf.sh ./Build/<mastermarkdown> <output.pdf>"
   echo
   exit
}

while getopts ":h" option; do
   case $option in
      h | *) # display Help
         Help
         exit;;
   esac
done

if [ -z "$1" ]
then
   Help
   exit
fi

SCRIPT=$(readlink -f "$0")
SCRIPTPATH=$(dirname "$SCRIPT")
echo "Running Pandoc to generate the LaTeX file..."
pandoc "$1" \
    -f gfm \
    --toc \
    --listings \
    --include-in-header ${SCRIPTPATH}/chapter_break.tex \
    --include-in-header ${SCRIPTPATH}/inline_code.tex \
    --include-in-header ${SCRIPTPATH}/bullet_style.tex \
    --include-in-header ${SCRIPTPATH}/pdf_properties.tex \
    --include-in-header ${SCRIPTPATH}/listings-setup.tex \
    --highlight-style ${SCRIPTPATH}/pygments.theme \
    -V toc-title='Table of contents' \
    -V linkcolor:blue \
    -V geometry:a4paper \
    -V geometry:margin=2cm \
    -V mainfont="DejaVu Serif" \
    -V monofont="DejaVu Sans Mono" \
    --pdf-engine=xelatex \
    -o /tmp/temp.tex

echo "Running Perl to format the output..."
fn="${2%.*}"

perl -0777 -pe 's/begin\{document\}\n\n\K(.*?^\}$)(.+?)\n/$2\n\\thispagestyle{empty}\n\n$1\n/ms' /tmp/temp.tex > ${SCRIPTPATH}/${fn}.tex

echo "Generating PDF (first pass)..."
cd ${SCRIPTPATH}
xelatex -interaction=nonstopmode ${fn}.tex > pdfgen.log 2>&1

echo "Generating PDF (second pass for TOC)..."
xelatex -interaction=nonstopmode ${fn}.tex >> pdfgen.log 2>&1

echo "Cleaning temp files..."
rm /tmp/temp.tex "$fn".{tex,toc,aux,log}

