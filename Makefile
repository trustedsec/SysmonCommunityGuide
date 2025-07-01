# Sysmon Community Guide Makefile
# Provides simple commands for building the guide

.PHONY: all build pdf clean validate docker help install-deps check-deps docker-build docker-pdf dev install-deps-mac

# Default target
all: build

# Build master markdown document
build:
	@echo "Building master document..."
	./build.sh build

# Build master document and generate PDF
pdf:
	@echo "Building PDF..."
	./build.sh pdf

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	./build.sh clean

# Validate chapter files and configuration
validate:
	@echo "Validating files..."
	./build.sh validate

# Build using Docker (recommended for production)
docker:
	@echo "Building with Docker..."
	./build.sh docker

# Build PDF using Docker
docker-pdf:
	@echo "Building PDF with Docker..."
	docker-compose run --rm pdf-builder

# Development environment (interactive Docker container)
dev:
	@echo "Starting development environment..."
	docker-compose run --rm dev

# Install dependencies (Ubuntu/Debian)
install-deps:
	@echo "Installing dependencies..."
	@command -v apt-get >/dev/null 2>&1 || { echo "This target only works on Debian/Ubuntu systems"; exit 1; }
	sudo apt-get update
	sudo apt-get install -y python3 python3-pip pandoc texlive-xetex texlive-latex-extra texlive-fonts-extra fonts-dejavu

# Install dependencies (macOS with Homebrew)
install-deps-mac:
	@echo "Installing dependencies for macOS..."
	@command -v brew >/dev/null 2>&1 || { echo "Homebrew is required. Install from https://brew.sh/"; exit 1; }
	brew install python3 pandoc
	brew install --cask mactex

# Check if all dependencies are available
check-deps:
	@echo "Checking dependencies..."
	./build.sh validate

# Build Docker image
docker-build:
	@echo "Building Docker image..."
	docker-compose build

# Show help
help:
	@echo "Sysmon Community Guide Build System"
	@echo ""
	@echo "Available targets:"
	@echo "  build          Build master markdown document"
	@echo "  pdf            Build master document and generate PDF"
	@echo "  clean          Clean build artifacts"
	@echo "  validate       Validate chapter files and configuration"
	@echo "  docker         Build using Docker container"
	@echo "  docker-pdf     Build PDF using Docker container"
	@echo "  dev            Start interactive development environment"
	@echo "  install-deps   Install dependencies (Ubuntu/Debian)"
	@echo "  install-deps-mac Install dependencies (macOS)"
	@echo "  check-deps     Check if all dependencies are installed"
	@echo "  docker-build   Build Docker image"
	@echo "  help           Show this help message"
	@echo ""
	@echo "Examples:"
	@echo "  make           # Build master document"
	@echo "  make pdf       # Generate PDF"
	@echo "  make docker    # Build using Docker"
	@echo "  make clean     # Clean build files"