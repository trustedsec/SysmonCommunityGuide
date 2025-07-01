# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is the TrustedSec Sysmon Community Guide - an open source documentation project that provides comprehensive guidance on Microsoft Sysinternals Sysmon for both Windows and Linux. The repository contains educational security content focused on defensive monitoring and detection capabilities.

## Repository Structure

- `chapters/` - Individual markdown files covering specific Sysmon topics and event types
- `Build/` - PDF generation tools and LaTeX configuration files
- `examples/` - Sample Sysmon XML configuration files
- `chapters/media/` - Images and screenshots used in the documentation

## Content Architecture

The guide follows a structured approach:
- Introduction to Sysmon concepts (`what-is-sysmon.md`)
- Platform-specific installation guides (`install_windows.md`, `install_linux.md`)  
- Event type documentation organized by category (process events, file events, network events, etc.)
- Each event type has its own dedicated chapter with examples and detection guidance

## Common Tasks

### Automated Build System
The repository now includes an automated build system that assembles individual chapters into a master document:

```bash
# Build master document from individual chapters
make build
python3 build_guide.py

# Generate PDF (requires pandoc, xelatex)
make pdf
./build.sh pdf

# Build using Docker (no local dependencies)
make docker

# Validate chapter files and configuration
make validate
./build.sh validate

# Clean build artifacts
make clean
```

### Legacy PDF Generation
```bash
# Generate PDF from existing master markdown (legacy method)
./Build/md2pdf.sh ./Build/Sysmon.md SysmonGuide.pdf
```

### Content Guidelines
- All content focuses on defensive security monitoring and detection
- Examples use legitimate security configurations and detection rules
- Content follows Creative Commons Attribution-ShareAlike 4.0 license
- Each chapter should be self-contained but reference related concepts

### File Naming Conventions
- Chapter files use lowercase with hyphens: `process-creation.md`
- Media files are numbered sequentially: `image1.png`, `image2.png`
- Configuration examples use descriptive names: `Exchange_CVE_2021_26855.xml`

## Build System Architecture

### New Automated System
- **Chapter Manifest**: `chapters.json` defines chapter order and metadata
- **Build Script**: `build_guide.py` automatically assembles individual chapters  
- **Docker Support**: `Dockerfile` and `docker-compose.yml` for containerized builds
- **CI/CD**: GitHub Actions workflow for automated validation and builds
- **Make Integration**: `Makefile` provides simple build commands

### Chapter Assembly Process
1. Reads chapter structure from `chapters.json`
2. Validates all referenced chapter files exist
3. Combines individual markdown files in correct order
4. Adjusts image paths for build directory
5. Adds metadata header with current date
6. Outputs master `Build/Sysmon.md` file

## Technical Notes

- PDF generation uses Pandoc with XeLaTeX engine
- Custom styling defined in `Build/` directory LaTeX files
- Metadata for PDF generation stored in `Build/metadata.yml` and `chapters.json`
- All documentation written in GitHub Flavored Markdown
- Build system preserves exact PDF output format from original manual process