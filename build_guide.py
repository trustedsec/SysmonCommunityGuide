#!/usr/bin/env python3
"""
Automated Sysmon Guide Builder

This script automatically assembles individual chapter files into a master markdown
document for PDF generation, following the structure defined in chapters.json.
"""

import json
import os
import sys
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional


class GuideBuilder:
    def __init__(self, config_file: str = "chapters.json"):
        """Initialize the guide builder with configuration."""
        self.config_file = config_file
        self.config = self._load_config()
        self.base_path = Path(".")
        self.output_dir = Path("Build")
        self.missing_files = []
        
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from JSON file."""
        try:
            with open(self.config_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"Error: Configuration file '{self.config_file}' not found.")
            sys.exit(1)
        except json.JSONDecodeError as e:
            print(f"Error: Invalid JSON in '{self.config_file}': {e}")
            sys.exit(1)
    
    def _validate_files(self) -> bool:
        """Validate that all referenced chapter files exist."""
        def check_chapter(chapter: Dict[str, Any]) -> None:
            if 'file' in chapter:
                file_path = self.base_path / chapter['file']
                if not file_path.exists():
                    self.missing_files.append(str(file_path))
            
            if 'sections' in chapter:
                for section in chapter['sections']:
                    check_chapter(section)
        
        for chapter in self.config['chapters']:
            check_chapter(chapter)
        
        if self.missing_files:
            print("Error: Missing chapter files:")
            for file in self.missing_files:
                print(f"  - {file}")
            return False
        
        return True
    
    def _read_chapter_content(self, file_path: str) -> str:
        """Read and return the content of a chapter file."""
        try:
            full_path = self.base_path / file_path
            with open(full_path, 'r', encoding='utf-8') as f:
                content = f.read().strip()
                
            # Adjust image paths to be relative to the Build directory
            # Convert chapters/media/imageX.png to ./media/imageX.png
            content = content.replace('chapters/media/', './media/')
            content = content.replace('](media/', '](./media/')
            
            # Remove existing headings from chapter content
            lines = content.split('\n')
            filtered_lines = []
            i = 0
            
            while i < len(lines):
                line = lines[i]
                
                # Skip markdown-style headings (# ## ### etc.)
                if line.startswith('#'):
                    i += 1
                    continue
                
                # Check for setext-style headings (underlined with = or -)
                if (i + 1 < len(lines) and 
                    line.strip() and 
                    lines[i + 1].strip() and
                    len(set(lines[i + 1].strip())) == 1 and
                    (lines[i + 1].strip()[0] == '=' or lines[i + 1].strip()[0] == '-')):
                    # Skip both the heading line and underline
                    i += 2
                    continue
                
                filtered_lines.append(line)
                i += 1
            
            return '\n'.join(filtered_lines)
        except Exception as e:
            print(f"Error reading {file_path}: {e}")
            return f"<!-- Error reading {file_path}: {e} -->"
    
    def _generate_heading(self, title: str, level: int) -> str:
        """Generate markdown heading with appropriate level."""
        return f"{'#' * level} {title}\n\n"
    
    def _process_chapter(self, chapter: Dict[str, Any], level: int = 1) -> str:
        """Process a chapter and its sections recursively with hierarchical heading levels."""
        content = []

        # Add chapter heading if it has a title - use the current level
        if 'title' in chapter:
            content.append(self._generate_heading(chapter['title'], level))

        # Add chapter content if it has a file
        if 'file' in chapter:
            chapter_content = self._read_chapter_content(chapter['file'])
            content.append(chapter_content)
            content.append("\n\n")

        # Process sections recursively - increment level for subsections
        if 'sections' in chapter:
            for section in chapter['sections']:
                section_content = self._process_chapter(section, level + 1)
                content.append(section_content)

        return ''.join(content)
    
    def _generate_metadata_header(self) -> str:
        """Generate YAML metadata header for the document."""
        metadata = self.config.get('metadata', {})
        
        # Add current date
        metadata['date'] = datetime.now().strftime("%d.%m.%Y")
        
        header = ["---"]
        for key, value in metadata.items():
            if key == 'cover_image':
                # Adjust cover image path for Build directory
                value = value.replace('chapters/', './')
            header.append(f"{key.replace('_', '-')}: \"{value}\"")
        header.append("---\n")
        
        return '\n'.join(header)
    
    def _add_cover_image(self) -> str:
        """Add cover image if specified with size constraints."""
        # Add page break after TOC to start content on fresh page
        # The logo will be added at the start of the first chapter
        return "\\newpage\n\n"
    
    def build_master_document(self) -> str:
        """Build the complete master document."""
        print("Building master document...")

        # Validate all files exist
        if not self._validate_files():
            return ""

        content = []

        # Add metadata header
        content.append(self._generate_metadata_header())

        # Add page break after TOC
        content.append(self._add_cover_image())

        # Add logo before first chapter
        cover_image = self.config.get('metadata', {}).get('cover_image')
        if cover_image:
            cover_path = cover_image.replace('chapters/', './')
            content.append(f'<img src="{cover_path}" width="100" />\n\n')

        # Process all chapters
        for chapter in self.config['chapters']:
            chapter_content = self._process_chapter(chapter)
            content.append(chapter_content)

        return ''.join(content)
    
    def save_master_document(self, content: str, filename: str = "Sysmon.md") -> None:
        """Save the master document to the Build directory."""
        output_path = self.output_dir / filename
        
        # Ensure Build directory exists
        self.output_dir.mkdir(exist_ok=True)
        
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(content)
            print(f"Master document saved to: {output_path}")
        except Exception as e:
            print(f"Error saving master document: {e}")
            sys.exit(1)
    
    def copy_media_files(self) -> None:
        """Copy media files to Build directory."""
        source_media = Path("chapters/media")
        dest_media = self.output_dir / "media"
        
        if source_media.exists():
            print("Copying media files...")
            dest_media.mkdir(exist_ok=True)
            
            for media_file in source_media.glob("*"):
                if media_file.is_file():
                    dest_file = dest_media / media_file.name
                    try:
                        import shutil
                        shutil.copy2(media_file, dest_file)
                    except Exception as e:
                        print(f"Warning: Could not copy {media_file}: {e}")
        
    def build(self) -> None:
        """Main build process."""
        print(f"Starting Sysmon Guide build process...")
        print(f"Configuration: {self.config_file}")
        print(f"Output directory: {self.output_dir}")
        
        # Copy media files
        self.copy_media_files()
        
        # Build master document
        master_content = self.build_master_document()
        
        if master_content:
            self.save_master_document(master_content)
            print("Build completed successfully!")
            print(f"Run './Build/md2pdf.sh ./Build/Sysmon.md SysmonGuide.pdf' to generate PDF")
        else:
            print("Build failed!")
            sys.exit(1)


def main():
    """Main entry point."""
    if len(sys.argv) > 1:
        config_file = sys.argv[1]
    else:
        config_file = "chapters.json"
    
    builder = GuideBuilder(config_file)
    builder.build()


if __name__ == "__main__":
    main()