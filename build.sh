#!/bin/bash

# Enhanced Sysmon Guide Build Script
# Provides automated chapter assembly and PDF generation with validation

set -e  # Exit on any error

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/Build"
CHAPTERS_CONFIG="${SCRIPT_DIR}/chapters.json"
MASTER_FILE="${BUILD_DIR}/Sysmon.md"
OUTPUT_PDF="SysmonGuide.pdf"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Help function
show_help() {
    cat << EOF
Sysmon Community Guide Build Script

USAGE:
    $0 [OPTIONS] [COMMAND]

COMMANDS:
    build       Build master markdown document (default)
    pdf         Build master document and generate PDF
    clean       Clean build artifacts
    validate    Validate chapter files and configuration
    docker      Build using Docker container
    help        Show this help message

OPTIONS:
    -c, --config FILE    Use alternative chapters.json file
    -o, --output FILE    Output PDF filename (default: $OUTPUT_PDF)
    -v, --verbose        Enable verbose output
    -q, --quiet          Suppress non-error output
    --no-validation      Skip file validation
    --force              Force rebuild even if files haven't changed

EXAMPLES:
    $0                          # Build master document
    $0 pdf                      # Build document and generate PDF
    $0 --config custom.json     # Use custom configuration
    $0 pdf --output MyGuide.pdf # Generate PDF with custom name
    $0 docker                   # Build using Docker

EOF
}

# Parse command line arguments
VERBOSE=false
QUIET=false
VALIDATE=true
FORCE=false
COMMAND="build"

while [[ $# -gt 0 ]]; do
    case $1 in
        -c|--config)
            CHAPTERS_CONFIG="$2"
            shift 2
            ;;
        -o|--output)
            OUTPUT_PDF="$2"
            shift 2
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -q|--quiet)
            QUIET=true
            shift
            ;;
        --no-validation)
            VALIDATE=false
            shift
            ;;
        --force)
            FORCE=true
            shift
            ;;
        build|pdf|clean|validate|docker|help)
            COMMAND="$1"
            shift
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

# Conditional logging based on quiet flag
log_cmd() {
    if [[ "$QUIET" != "true" ]]; then
        log_info "$1"
    fi
}

log_verbose() {
    if [[ "$VERBOSE" == "true" ]]; then
        log_info "$1"
    fi
}

# Validation functions
check_dependencies() {
    local missing_deps=()
    
    if ! command -v python3 &> /dev/null; then
        missing_deps+=("python3")
    fi
    
    if [[ "$COMMAND" == "pdf" ]]; then
        if ! command -v pandoc &> /dev/null; then
            missing_deps+=("pandoc")
        fi
        
        # Add MacTeX to PATH for dependency check
        if [[ -d "/usr/local/texlive" ]]; then
            TEXLIVE_BIN=$(find /usr/local/texlive -name "xelatex" 2>/dev/null | head -1)
            if [[ -n "$TEXLIVE_BIN" ]]; then
                export PATH="$(dirname "$TEXLIVE_BIN"):$PATH"
            fi
        fi
        
        if ! command -v xelatex &> /dev/null; then
            missing_deps+=("xelatex")
        fi
    fi
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        log_error "Missing required dependencies:"
        for dep in "${missing_deps[@]}"; do
            echo "  - $dep"
        done
        log_info "Consider using Docker build: $0 docker"
        exit 1
    fi
}

validate_config() {
    if [[ ! -f "$CHAPTERS_CONFIG" ]]; then
        log_error "Configuration file not found: $CHAPTERS_CONFIG"
        exit 1
    fi
    
    if ! python3 -c "import json; json.load(open('$CHAPTERS_CONFIG'))" 2>/dev/null; then
        log_error "Invalid JSON in configuration file: $CHAPTERS_CONFIG"
        exit 1
    fi
    
    log_verbose "Configuration file validated: $CHAPTERS_CONFIG"
}

validate_chapters() {
    log_cmd "Validating chapter files..."
    
    if ! python3 -c "
import json
import sys
from pathlib import Path

config = json.load(open('$CHAPTERS_CONFIG'))
missing = []

def check_chapter(chapter):
    if 'file' in chapter:
        if not Path(chapter['file']).exists():
            missing.append(chapter['file'])
    if 'sections' in chapter:
        for section in chapter['sections']:
            check_chapter(section)

for chapter in config['chapters']:
    check_chapter(chapter)

if missing:
    print('Missing chapter files:')
    for f in missing:
        print(f'  - {f}')
    sys.exit(1)
"; then
        log_error "Chapter validation failed"
        exit 1
    fi
    
    log_success "All chapter files validated"
}

# Build functions
build_master() {
    log_cmd "Building master document..."
    
    if [[ "$VALIDATE" == "true" ]]; then
        validate_config
        validate_chapters
    fi
    
    # Check if rebuild is needed (unless forced)
    if [[ "$FORCE" != "true" ]] && [[ -f "$MASTER_FILE" ]]; then
        local config_time=$(stat -f %m "$CHAPTERS_CONFIG" 2>/dev/null || stat -c %Y "$CHAPTERS_CONFIG" 2>/dev/null)
        local master_time=$(stat -f %m "$MASTER_FILE" 2>/dev/null || stat -c %Y "$MASTER_FILE" 2>/dev/null)
        
        if [[ "$master_time" -gt "$config_time" ]]; then
            # Check if any chapter files are newer
            local rebuild_needed=false
            while IFS= read -r chapter_file; do
                if [[ -f "$chapter_file" ]]; then
                    local chapter_time=$(stat -f %m "$chapter_file" 2>/dev/null || stat -c %Y "$chapter_file" 2>/dev/null)
                    if [[ "$chapter_time" -gt "$master_time" ]]; then
                        rebuild_needed=true
                        break
                    fi
                fi
            done < <(python3 -c "
import json
config = json.load(open('$CHAPTERS_CONFIG'))
def get_files(chapter):
    if 'file' in chapter:
        print(chapter['file'])
    if 'sections' in chapter:
        for section in chapter['sections']:
            get_files(section)
for chapter in config['chapters']:
    get_files(chapter)
")
            
            if [[ "$rebuild_needed" != "true" ]]; then
                log_info "Master document is up to date"
                return 0
            fi
        fi
    fi
    
    # Run Python build script
    if python3 build_guide.py "$CHAPTERS_CONFIG"; then
        log_success "Master document built successfully: $MASTER_FILE"
    else
        log_error "Failed to build master document"
        exit 1
    fi
}

build_pdf() {
    log_cmd "Generating PDF..."
    
    if [[ ! -f "$MASTER_FILE" ]]; then
        log_error "Master document not found. Run build first."
        exit 1
    fi
    
    # Ensure md2pdf.sh is executable
    chmod +x "${BUILD_DIR}/md2pdf.sh"
    
    # Add MacTeX to PATH if available
    if [[ -d "/usr/local/texlive" ]]; then
        TEXLIVE_BIN=$(find /usr/local/texlive -name "xelatex" 2>/dev/null | head -1)
        if [[ -n "$TEXLIVE_BIN" ]]; then
            export PATH="$(dirname "$TEXLIVE_BIN"):$PATH"
        fi
    fi
    
    # Change to build directory and run PDF generation
    cd "$BUILD_DIR"
    if ./md2pdf.sh "./Sysmon.md" "$OUTPUT_PDF"; then
        log_success "PDF generated successfully: ${BUILD_DIR}/${OUTPUT_PDF}"
    else
        log_error "Failed to generate PDF"
        exit 1
    fi
    cd "$SCRIPT_DIR"
}

clean_build() {
    log_cmd "Cleaning build artifacts..."

    local files_to_clean=(
        "${BUILD_DIR}/Sysmon.md"
        "${BUILD_DIR}/${OUTPUT_PDF}"
        "${BUILD_DIR}/pdfgen.log"
        "${BUILD_DIR}/SysmonGuide.tex"
        "${BUILD_DIR}"/*.toc
        "${BUILD_DIR}"/*.aux
        "${BUILD_DIR}"/*.log
    )

    for file in "${files_to_clean[@]}"; do
        if [[ -f "$file" ]] || [[ -e "$file" ]]; then
            rm -f "$file"
            log_verbose "Removed: $file"
        fi
    done

    log_success "Build artifacts cleaned"
}

docker_build() {
    log_cmd "Building with Docker..."
    
    if ! command -v docker &> /dev/null; then
        log_error "Docker not found. Please install Docker first."
        exit 1
    fi
    
    case "$COMMAND" in
        docker)
            docker-compose run --rm sysmon-builder
            ;;
        pdf)
            docker-compose run --rm pdf-builder
            ;;
        *)
            docker-compose run --rm sysmon-builder
            ;;
    esac
}

# Main execution
main() {
    log_cmd "Sysmon Community Guide Build Script"
    log_verbose "Command: $COMMAND"
    log_verbose "Config: $CHAPTERS_CONFIG"
    log_verbose "Output: $OUTPUT_PDF"
    
    case "$COMMAND" in
        build)
            check_dependencies
            build_master
            ;;
        pdf)
            check_dependencies
            build_master
            build_pdf
            ;;
        clean)
            clean_build
            ;;
        validate)
            validate_config
            validate_chapters
            log_success "Validation completed successfully"
            ;;
        docker)
            docker_build
            ;;
        help)
            show_help
            ;;
        *)
            log_error "Unknown command: $COMMAND"
            show_help
            exit 1
            ;;
    esac
}

# Run main function
main "$@"