# Custom Cover Page Feature

## Overview
The PDF build process now automatically replaces the first page (auto-generated title page) with a custom cover image.

## Cover Image
- **Location**: `chapters/media/TS_SysmonCommunityGuide_Cover.png`
- **Format**: PNG
- **Size**: ~3 MB (high resolution)
- **Page Size**: Scaled to fit A4 with aspect ratio maintained

## Implementation

### Components
1. **`Build/replace_cover.py`** - Python script that handles cover replacement
   - Uses `pypdf` (or PyPDF2) to manipulate PDF pages
   - Uses `Pillow` to process cover image
   - Uses `reportlab` to convert image to PDF page
   - Maintains A4 page size and centers image

2. **`Build/md2pdf.sh`** - Updated to call cover replacement after PDF generation
   - Generates PDF with XeLaTeX (2 passes for TOC)
   - Checks for cover image existence
   - Replaces first page automatically
   - Handles errors gracefully (falls back to original if replacement fails)

3. **Dependencies** - Added Python packages:
   - `pypdf` - PDF manipulation
   - `Pillow` - Image processing
   - `reportlab` - PDF generation

### Build Process Flow
```
1. Pandoc converts Markdown → LaTeX
2. XeLaTeX generates PDF (2 passes)
3. Custom cover replacement:
   a. Check if TS_SysmonCommunityGuide_Cover.png exists
   b. Convert cover image to PDF page (A4, centered, scaled)
   c. Replace first page of generated PDF with cover
   d. Save final PDF
4. Clean up temporary files
```

## Usage

### Normal Build
```bash
# Just build as usual - cover replacement happens automatically
make pdf

# Or using build.sh
./build.sh pdf
```

### Installing Dependencies

**macOS:**
```bash
make install-deps-mac
# Or manually:
pip3 install --user --break-system-packages pypdf Pillow reportlab
```

**Ubuntu/Debian:**
```bash
make install-deps
# Or manually:
pip3 install pypdf Pillow reportlab
```

**Docker:**
```bash
# Dependencies already included in Docker image
make docker-pdf
```

## Customization

### Using a Different Cover Image
1. Replace `chapters/media/TS_SysmonCommunityGuide_Cover.png` with your image
2. Image can be any size - will be automatically scaled to fit A4
3. Maintains aspect ratio - will not distort
4. Centered on page

### Disabling Cover Replacement
If you want to use the default Pandoc-generated title page:
1. Remove or rename the cover image file, OR
2. Comment out the cover replacement section in `Build/md2pdf.sh` (lines 64-80)

## Technical Details

### Image Processing
- Cover image is converted to a temporary PDF (`/tmp/cover_page.pdf`)
- Image is scaled to fit A4 (210mm × 297mm) while maintaining aspect ratio
- Image is centered on the page
- Uses high-quality rendering from Pillow

### PDF Manipulation
- Original PDF is temporarily renamed
- Cover page PDF is created with exact A4 dimensions
- First page of original PDF is replaced with cover
- All other pages (2-N) are copied unchanged
- Temporary files are cleaned up

### Error Handling
- Checks if cover image exists before attempting replacement
- Validates PDF was generated successfully
- Falls back to original PDF if replacement fails
- Provides clear error messages in build output

## Verification

After building, verify the cover replacement worked:

```bash
# Check PDF exists and has correct size
ls -lh Build/SysmonGuide.pdf

# Check number of pages
file Build/SysmonGuide.pdf

# Open PDF and visually inspect first page
open Build/SysmonGuide.pdf  # macOS
xdg-open Build/SysmonGuide.pdf  # Linux
```

## Troubleshooting

### "Module not found" errors
Install Python dependencies:
```bash
pip3 install --user --break-system-packages pypdf Pillow reportlab
```

### Cover replacement fails
Check build log for errors:
```bash
cat Build/pdfgen.log
```

### Cover image not found
Verify the image exists:
```bash
ls -lh chapters/media/TS_SysmonCommunityGuide_Cover.png
```

### PDF is too large
The cover image adds ~3MB to the PDF. To reduce size:
1. Optimize the cover image before building
2. Convert to lower DPI (e.g., 150 DPI instead of 300 DPI)
3. Use JPEG instead of PNG (with quality setting)

## Future Enhancements

Potential improvements:
- [ ] Support for back cover page
- [ ] Configurable cover image path in chapters.json
- [ ] Multiple cover formats (PDF, SVG, etc.)
- [ ] Automatic image optimization
- [ ] Cover template system
