# Sysmon Community Guide Build Environment
FROM ubuntu:22.04

# Avoid interactive prompts during build
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update && apt-get install -y \
    # Basic tools
    curl \
    wget \
    git \
    make \
    # Python for build scripts
    python3 \
    python3-pip \
    # LaTeX and fonts for PDF generation
    texlive-xetex \
    texlive-latex-extra \
    texlive-fonts-extra \
    texlive-fonts-recommended \
    # DejaVu fonts (specified in build script)
    fonts-dejavu \
    fonts-dejavu-core \
    fonts-dejavu-extra \
    # Pandoc dependencies
    pandoc \
    # Additional useful tools
    perl \
    && rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /guide

# Create a non-root user for building
RUN useradd -m -u 1000 builder && \
    chown -R builder:builder /guide

USER builder

# Set environment variables
ENV PYTHONPATH=/guide
ENV PATH=/home/builder/.local/bin:$PATH

# Default command
CMD ["python3", "build_guide.py"]

# Health check to verify tools are installed
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD pandoc --version && xelatex --version && python3 --version