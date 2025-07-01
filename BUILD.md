# Sysmon Community Guide - Build System

This document describes the automated build system for the Sysmon Community Guide.

## Overview

The new build system provides automated chapter assembly and PDF generation with the following improvements:

- **Automated Chapter Assembly**: No more manual maintenance of master markdown files
- **Dependency Management**: Docker containerization eliminates host dependency issues  
- **Validation**: Comprehensive file and configuration validation
- **CI/CD Integration**: GitHub Actions workflow for automated builds
- **Multiple Build Methods**: Native, Docker, and Make-based builds
- **Quality Preservation**: Maintains exact same PDF output as original system

## Quick Start

### Using Make (Recommended)
```bash
# Build master document
make build

# Generate PDF (requires pandoc, xelatex)
make pdf

# Build using Docker (no local dependencies)
make docker

# Clean build files
make clean
```

### Using Build Script Directly
```bash
# Build master document
./build.sh build

# Generate PDF
./build.sh pdf

# Validate files
./build.sh validate

# Build with Docker
./build.sh docker
```

### Using Python Script Directly
```bash
# Build master document
python3 build_guide.py

# Build with custom config
python3 build_guide.py custom-chapters.json
```

## Build Methods

### 1. Native Build
Requires local installation of dependencies:
- Python 3.7+
- pandoc
- xelatex (TeX Live)
- DejaVu fonts

**Ubuntu/Debian:**
```bash
make install-deps
```

**macOS:**
```bash
make install-deps-mac
```

### 2. Docker Build (Recommended)
No local dependencies required except Docker:

```bash
# Build master document
make docker

# Build PDF
make docker-pdf

# Interactive development
make dev
```

### 3. GitHub Actions
Automatic builds on:
- Pushes to master/main branch
- Pull requests affecting chapters
- Manual workflow dispatch

## Configuration

### Chapter Manifest (`chapters.json`)
Defines the structure and order of chapters:

```json
{
  "title": "Sysmon Community Guide",
  "metadata": {
    "title": "Sysmon Missing Manual",
    "author": "Carlos Perez",
    ...
  },
  "chapters": [
    {
      "title": "What is Sysmon",
      "file": "chapters/what-is-sysmon.md",
      "level": 1
    },
    ...
  ]
}
```

### Build Configuration
- **Input**: Individual chapter files in `chapters/` directory
- **Output**: Master document in `Build/Sysmon.md`
- **Media**: Automatically copied from `chapters/media/` to `Build/media/`
- **PDF**: Generated in `Build/` directory

## File Structure

```
SysmonCommunityGuide/
├── chapters.json           # Chapter manifest and metadata
├── build_guide.py         # Python build script
├── build.sh              # Enhanced shell build script
├── Makefile              # Simple make commands
├── Dockerfile            # Container build environment
├── docker-compose.yml    # Docker services
├── .github/workflows/    # CI/CD automation
├── chapters/             # Individual chapter files
│   ├── media/           # Images and assets
│   └── *.md             # Chapter markdown files
├── Build/               # Build output directory
│   ├── Sysmon.md        # Generated master document
│   ├── media/           # Copied media files
│   ├── *.tex           # LaTeX configuration
│   └── *.pdf           # Generated PDF
└── examples/            # Sample configurations
```

## Validation

The build system includes comprehensive validation:

- **JSON Configuration**: Validates `chapters.json` syntax
- **File Existence**: Ensures all referenced chapter files exist
- **Image Links**: Validates media file references
- **Build Dependencies**: Checks required tools are available

## PDF Generation

The PDF generation process:

1. **Chapter Assembly**: Combines individual chapters per manifest
2. **Media Processing**: Copies and adjusts image paths  
3. **Metadata Injection**: Adds YAML frontmatter with current date
4. **Pandoc Conversion**: Converts markdown to LaTeX
5. **XeLaTeX Compilation**: Generates final PDF with custom styling

### PDF Styling Preserved
- Custom LaTeX templates in `Build/` directory
- DejaVu Serif/Sans Mono fonts
- Chapter page breaks
- Syntax highlighting
- Custom bullet styles
- Proper margins and layout

## Troubleshooting

### Common Issues

**Missing Dependencies:**
```bash
make check-deps  # Check what's missing
make docker      # Use Docker instead
```

**Chapter Files Not Found:**
```bash
make validate    # Check file references
```

**PDF Generation Fails:**
```bash
# Check pandoc/xelatex installation
pandoc --version
xelatex --version

# Use Docker build instead
make docker-pdf
```

**Permission Issues:**
```bash
chmod +x build.sh
chmod +x build_guide.py
```

### Debug Mode

Enable verbose output:
```bash
./build.sh --verbose pdf
```

View build logs:
```bash
# Check pandoc log
cat Build/pdfgen.log

# Check Docker logs
docker-compose logs
```

## Development

### Adding New Chapters

1. Create chapter file in `chapters/` directory
2. Add entry to `chapters.json` manifest:
   ```json
   {
     "title": "New Chapter",
     "file": "chapters/new-chapter.md", 
     "level": 2
   }
   ```
3. Test the build:
   ```bash
   make validate
   make build
   ```

### Customizing Build

- **Modify Metadata**: Edit `chapters.json` metadata section
- **Change Chapter Order**: Reorder entries in `chapters.json`
- **Add Build Steps**: Extend `build_guide.py` or `build.sh`
- **Custom Styling**: Modify LaTeX files in `Build/` directory

### Contributing

The build system is designed to be maintainable and extensible:

- **Modular Design**: Separate concerns (assembly, validation, PDF generation)
- **Error Handling**: Comprehensive error checking and reporting
- **Documentation**: Inline code documentation and help text
- **Testing**: Validation and CI/CD integration

## Migration from Old System

The new system is backward compatible:

- **Existing `Build/Sysmon.md`**: Will be overwritten by automated build
- **LaTeX Templates**: Preserved exactly as before
- **PDF Output**: Identical to original system
- **Build Commands**: Enhanced but compatible

To migrate:
1. Use new build commands instead of manual editing
2. Update chapter content in individual files
3. Modify `chapters.json` for structural changes
4. Use Docker build for consistent environment