# Sysmon Community Guide - Build Process

This directory contains the automated build system for generating the Sysmon Community Guide PDF.

## Quick Start

### Prerequisites
- Python 3.7+
- pandoc
- XeLaTeX (TeX Live)
- DejaVu fonts

### Build Commands

From the project root directory:

```bash
# Generate PDF (recommended)
make pdf

# Or use build script directly
./build.sh pdf

# Build master document only
make build

# Validate files and dependencies
make check-deps
```

## Build Process Overview

The automated build system:

1. **Assembles Chapters**: Reads `chapters.json` configuration and combines individual chapter files
2. **Removes Headings**: Strips existing headings from chapters and uses level-1 headings only
3. **Generates Master**: Creates `Build/Sysmon.md` with proper metadata and structure
4. **Copies Media**: Transfers images from `chapters/media/` to `Build/media/`
5. **Creates PDF**: Uses Pandoc + XeLaTeX with custom styling and table of contents

## Installation Options

### Option 1: Native Installation (macOS)
```bash
# Install dependencies
make install-deps-mac

# Or manually:
brew install python3 pandoc
brew install --cask mactex
brew install --cask font-dejavu
```

### Option 2: Native Installation (Ubuntu/Debian)
```bash
# Install dependencies
make install-deps

# Or manually:
sudo apt-get install python3 pandoc texlive-xetex texlive-latex-extra texlive-fonts-extra fonts-dejavu
```

### Option 3: Docker (Recommended for CI/CD)
```bash
# Build using Docker (no local dependencies)
make docker-pdf

# Or for development
make dev
```

## Build Outputs

- `Build/Sysmon.md` - Master markdown document
- `Build/SysmonGuide.pdf` - Final PDF output (87 pages)
- `Build/media/` - Copied image assets
- `Build/pdfgen.log` - PDF generation log

## Troubleshooting

### Common Issues

**Error: "xelatex not found"**
```bash
# Check if MacTeX is installed
ls /usr/local/texlive/*/bin/*/xelatex

# Or use Docker build
make docker-pdf
```

**Error: "pandoc not found"**
```bash
# Install pandoc
brew install pandoc  # macOS
sudo apt install pandoc  # Ubuntu/Debian
```

**Error: Missing chapter files**
```bash
# Validate configuration
make validate
./build.sh validate
```

**Error: Images not found**
```bash
# Ensure media files are copied
python3 build_guide.py
```

### Debug Mode
```bash
# Enable verbose output
./build.sh --verbose pdf

# Check build log
cat Build/pdfgen.log
```

## Configuration

### Chapter Structure (`chapters.json`)
```json
{
  "metadata": {
    "title": "Sysmon Missing Manual",
    "author": "Carlos Perez"
  },
  "chapters": [
    {
      "title": "Chapter Title",
      "file": "chapters/chapter-file.md",
      "level": 1
    }
  ]
}
```

### Build Customization

**Custom Output Name:**
```bash
./build.sh pdf --output MyCustomGuide.pdf
```

**Skip Validation:**
```bash
./build.sh pdf --no-validation
```

**Force Rebuild:**
```bash
./build.sh pdf --force
```

## Build System Architecture

### Files
- `../build_guide.py` - Python chapter assembly script
- `../build.sh` - Enhanced shell build script with validation
- `../Makefile` - Simple build commands
- `../chapters.json` - Chapter configuration and metadata
- `md2pdf.sh` - LaTeX PDF generation script
- `*.tex` - LaTeX styling templates
- `pygments.theme` - Syntax highlighting theme

### Process Flow
```
chapters.json → Python Script → Build/Sysmon.md → Pandoc → XeLaTeX → PDF
     ↓              ↓               ↓           ↓        ↓        ↓
Configuration  Assembly      Master Doc    LaTeX    Styling   Final PDF
```

## Advanced Usage

### Development Workflow
```bash
# Interactive development environment
make dev

# Build and test changes
make build
make pdf
```

### CI/CD Integration
```bash
# GitHub Actions ready
make docker-pdf

# Validation only
make validate
```

### Custom Styling
- Modify LaTeX files in `Build/` directory
- Edit `pandoc.css` for HTML styling
- Update `pygments.theme` for code highlighting

## Performance Notes

- **First Build**: ~2-3 minutes (downloads Docker images)
- **Subsequent Builds**: ~30-60 seconds
- **Chapter Changes**: Auto-detected, rebuilds only when needed
- **Media Optimization**: Images copied only when changed

## Support

For build issues:
1. Check this README
2. Run `make validate` for diagnostics
3. Review `Build/pdfgen.log` for errors
4. Use Docker build as fallback: `make docker-pdf`

For content issues, see the main project README.