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
echo -e "\e[1;32m Running Pandoc to generate the LaTex file. \e[0m"
pandoc "$1" \
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
    -o /tmp/temp.tex

echo -e "\e[1;32m Running Perl to format the output. \e[0m"
fn="${2%.*}"

perl -0777 -pe 's/begin\{document\}\n\n\K(.*?^\}$)(.+?)\n/$2\n\\thispagestyle{empty}\n\n$1\n/ms' /tmp/temp.tex > ${SCRIPTPATH}/${fn}.tex

echo -e "\e[1;32m Generating PDF. \e[0m"
xelatex ${SCRIPTPATH}/${fn}.tex > ${SCRIPTPATH}/pdfgen.log

echo -e "\e[1;32m Cleanning temp files. \e[0m"
rm /tmp/temp.tex "$fn".{tex,toc,aux,log}

