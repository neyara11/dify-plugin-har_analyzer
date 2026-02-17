#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Build Dify plugin package (.difypkg)
"""

import os
import sys
import zipfile
import hashlib
from pathlib import Path


def calculate_sha256(file_path: str) -> str:
    """Calculate SHA256 hash"""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def create_difypkg(plugin_dir: str, output_name: str = None):
    """Create .difypkg package"""
    
    plugin_path = Path(plugin_dir).resolve()
    
    if not plugin_path.exists():
        print(f"Error: Directory not found: {plugin_dir}")
        return False
    
    manifest_path = plugin_path / "manifest.yaml"
    if not manifest_path.exists():
        print(f"Error: manifest.yaml not found in {plugin_dir}")
        return False
    
    # Check icon in _assets
    icon_path = plugin_path / "_assets" / "icon.svg"
    if not icon_path.exists():
        print(f"Error: Icon not found: _assets/icon.svg")
        return False
    
    if output_name is None:
        output_name = "haranalyzer.difypkg"
    
    output_path = plugin_path / output_name
    
    # Files to exclude
    exclude_names = {
        '__pycache__',
        '.git',
        '.gitignore',
        '.env',
        '.env.example',
        'venv',
        '.venv',
        '.DS_Store',
        'Thumbs.db',
        'build_package.py',
        '.sha256',
        output_name,
        'README.md',
        'pyproject.toml',
        '.python-version',
    }
    
    def should_include(file_path: Path) -> bool:
        name = file_path.name
        if name in exclude_names:
            return False
        if name.endswith('.pyc'):
            return False
        if name.startswith('~'):
            return False
        # Include hidden files in _assets (like .env.example for reference)
        if name.startswith('.') and '_assets' not in str(file_path):
            return False
        return True
    
    print(f"Building package from: {plugin_path}")
    print(f"Output: {output_path}")
    
    try:
        files_added = []
        
        with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zf:
            for root, dirs, files in os.walk(plugin_path):
                # Filter directories
                dirs[:] = [d for d in dirs if should_include(Path(root) / d)]
                
                for file in files:
                    file_path = Path(root) / file
                    rel_path = file_path.relative_to(plugin_path)
                    
                    if not should_include(file_path):
                        continue
                    
                    zf.write(file_path, str(rel_path))
                    files_added.append(str(rel_path))
                    print(f"  + {rel_path}")
        
        sha256 = calculate_sha256(str(output_path))
        file_size = output_path.stat().st_size
        
        print(f"\nFiles added: {len(files_added)}")
        print(f"Package created: {output_path}")
        print(f"Size: {file_size:,} bytes")
        print(f"SHA256: {sha256}")
        
        # Show contents
        print(f"\nPackage contents:")
        with zipfile.ZipFile(output_path, 'r') as zf:
            for name in sorted(zf.namelist()):
                info = zf.getinfo(name)
                print(f"   {name} ({info.file_size} bytes)")
        
        return True
        
    except Exception as e:
        print(f"Error creating package: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    script_dir = Path(__file__).parent.resolve()
    plugin_dir = script_dir
    
    if len(sys.argv) > 1:
        plugin_dir = Path(sys.argv[1]).resolve()
    
    output_name = None
    if len(sys.argv) > 2:
        output_name = sys.argv[2]
    
    success = create_difypkg(str(plugin_dir), output_name)
    
    if success:
        print("\nDone! Upload haranalyzer.difypkg to Dify:")
        print("   Settings -> Plugins -> Upload Plugin")
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
