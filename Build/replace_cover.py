#!/usr/bin/env python3
"""
Replace the first page of a PDF with a custom cover image.
"""

import sys
import os
from pathlib import Path

def check_dependencies():
    """Check if required libraries are installed."""
    missing = []

    try:
        import pypdf
    except ImportError:
        try:
            import PyPDF2
        except ImportError:
            missing.append("pypdf or PyPDF2")

    try:
        from PIL import Image
    except ImportError:
        missing.append("Pillow")

    try:
        import reportlab
    except ImportError:
        missing.append("reportlab")

    if missing:
        print(f"Error: Missing required Python packages: {', '.join(missing)}", file=sys.stderr)
        print("\nInstall with:", file=sys.stderr)
        print("  pip3 install pypdf Pillow reportlab", file=sys.stderr)
        return False

    return True

def create_cover_pdf(image_path, output_pdf):
    """Convert cover image to a PDF page."""
    from reportlab.pdfgen import canvas
    from reportlab.lib.pagesizes import letter, A4
    from PIL import Image

    # Open the image to get dimensions
    img = Image.open(image_path)
    img_width, img_height = img.size

    # Use A4 page size to match the rest of the document
    page_width, page_height = A4

    # Calculate scaling to fit image on page while maintaining aspect ratio
    width_ratio = page_width / img_width
    height_ratio = page_height / img_height
    scale_ratio = min(width_ratio, height_ratio)

    # Calculate final dimensions
    final_width = img_width * scale_ratio
    final_height = img_height * scale_ratio

    # Center the image on the page
    x_offset = (page_width - final_width) / 2
    y_offset = (page_height - final_height) / 2

    # Create PDF with the image
    c = canvas.Canvas(output_pdf, pagesize=A4)
    c.drawImage(image_path, x_offset, y_offset, width=final_width, height=final_height)
    c.save()

    print(f"Created cover PDF: {output_pdf}")

def replace_first_page(pdf_path, cover_image_path, output_path):
    """Replace the first page of a PDF with a cover image."""

    # Import the appropriate library
    try:
        from pypdf import PdfWriter, PdfReader
    except ImportError:
        from PyPDF2 import PdfWriter, PdfReader

    # Create temporary cover PDF
    temp_cover = "/tmp/cover_page.pdf"
    create_cover_pdf(cover_image_path, temp_cover)

    # Read the original PDF and cover PDF
    original_pdf = PdfReader(pdf_path)
    cover_pdf = PdfReader(temp_cover)

    # Create a new PDF writer
    output = PdfWriter()

    # Add the cover page
    output.add_page(cover_pdf.pages[0])

    # Add all pages from original PDF except the first one
    for i in range(1, len(original_pdf.pages)):
        output.add_page(original_pdf.pages[i])

    # Write the output PDF
    with open(output_path, 'wb') as output_file:
        output.write(output_file)

    # Clean up temporary file
    os.remove(temp_cover)

    print(f"Successfully replaced first page with cover image")
    print(f"Output: {output_path}")

def main():
    if len(sys.argv) != 4:
        print("Usage: replace_cover.py <input.pdf> <cover_image.png> <output.pdf>")
        sys.exit(1)

    pdf_path = sys.argv[1]
    cover_image_path = sys.argv[2]
    output_path = sys.argv[3]

    # Validate inputs
    if not os.path.exists(pdf_path):
        print(f"Error: PDF file not found: {pdf_path}", file=sys.stderr)
        sys.exit(1)

    if not os.path.exists(cover_image_path):
        print(f"Error: Cover image not found: {cover_image_path}", file=sys.stderr)
        sys.exit(1)

    # Check dependencies
    if not check_dependencies():
        sys.exit(1)

    # Replace the first page
    try:
        replace_first_page(pdf_path, cover_image_path, output_path)
    except Exception as e:
        print(f"Error: Failed to replace cover page: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
