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
    -f markdown \
    --toc \
    --toc-depth=3 \
    --listings \
    --include-in-header ${SCRIPTPATH}/chapter_break.tex \
    --include-in-header ${SCRIPTPATH}/inline_code.tex \
    --include-in-header ${SCRIPTPATH}/bullet_style.tex \
    --include-in-header ${SCRIPTPATH}/pdf_properties.tex \
    --include-in-header ${SCRIPTPATH}/listings-setup.tex \
    --include-in-header ${SCRIPTPATH}/toc-styling.tex \
    --include-in-header ${SCRIPTPATH}/title_page.tex \
    --include-in-header ${SCRIPTPATH}/toc_pagebreak.tex \
    --highlight-style ${SCRIPTPATH}/pygments.theme \
    -V toc-title='Sysmon Guide Contents' \
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

# Replace first page with custom cover if cover image exists
COVER_IMAGE="${SCRIPTPATH}/../chapters/media/TS_SysmonCommunityGuide_Cover.png"
if [ -f "$COVER_IMAGE" ]; then
    echo "Replacing first page with custom cover..."
    TEMP_PDF="${fn}_temp.pdf"
    mv "${fn}.pdf" "$TEMP_PDF"

    if python3 "${SCRIPTPATH}/replace_cover.py" "$TEMP_PDF" "$COVER_IMAGE" "${fn}.pdf"; then
        echo "Cover page replaced successfully"
        rm "$TEMP_PDF"
    else
        echo "Warning: Failed to replace cover page, using original PDF"
        mv "$TEMP_PDF" "${fn}.pdf"
    fi
else
    echo "Warning: Cover image not found at $COVER_IMAGE, skipping cover replacement"
fi

echo "Cleaning temp files..."
rm /tmp/temp.tex "$fn".{tex,toc,aux,log}

