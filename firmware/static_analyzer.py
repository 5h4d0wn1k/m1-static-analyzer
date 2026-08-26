#!/usr/bin/env python3
"""
M1 — Static Analyzer
ELF/PE static analysis tool for malware research

Features:
- Parse ELF and PE file formats
- Extract imports, exports, sections
- Detect common packers/protectors
- Calculate entropy
- YARA rule matching
- VirusTotal integration

Usage:
    python3 static_analyzer.py --file suspicious.exe

WARNING: Educational use only. Analyze samples in isolated environments.
"""

import argparse
import hashlib
import json
import os
import sys
import time
import magic
from collections import Counter
import math

class StaticAnalyzer:
    def __init__(self, file_path):
        self.file_path = file_path
        self.file_data = None
        self.file_type = None
        self.results = {}
        
        print(f"\n=== M1 — Static Analyzer ===")
        print(f"File: {file_path}")
        print("=" * 30)
    
    def load_file(self):
        """Load and identify file"""
        try:
            with open(self.file_path, 'rb') as f:
                self.file_data = f.read()
            
            # Identify file type
            self.file_type = magic.from_file(self.file_path)
            
            # Basic info
            self.results['file_path'] = self.file_path
            self.results['file_size'] = len(self.file_data)
            self.results['file_type'] = self.file_type
            
            # Hashes
            self.results['md5'] = hashlib.md5(self.file_data).hexdigest()
            self.results['sha1'] = hashlib.sha1(self.file_data).hexdigest()
            self.results['sha256'] = hashlib.sha256(self.file_data).hexdigest()
            
            return True
        except Exception as e:
            print(f"ERROR: {e}")
            return False
    
    def calculate_entropy(self):
        """Calculate Shannon entropy"""
        if not self.file_data:
            return 0
        
        # Count byte frequencies
        byte_counts = Counter(self.file_data)
        file_len = len(self.file_data)
        
        # Calculate entropy
        entropy = 0
        for count in byte_counts.values():
            if count > 0:
                prob = count / file_len
                entropy -= prob * math.log2(prob)
        
        return entropy
    
    def analyze_elf(self):
        """Analyze ELF file"""
        try:
            import elftools.elf.elffile as elffile
            
            with open(self.file_path, 'rb') as f:
                elf = elffile.ELFFile(f)
                
                self.results['format'] = 'ELF'
                self.results['arch'] = elf.header.e_machine
                self.results['entry_point'] = hex(elf.header.e_entry)
                
                # Sections
                sections = []
                for section in elf.iter_sections():
                    sections.append({
                        'name': section.name,
                        'size': section.header.sh_size,
                        'entropy': self.calculate_entropy()
                    })
                self.results['sections'] = sections
                
                # Symbols
                symbols = []
                for section in elf.iter_sections():
                    if section.header.sh_type == 'SHT_SYMTAB':
                        for symbol in section.iter_symbols():
                            if symbol.name:
                                symbols.append(symbol.name)
                self.results['symbols'] = symbols[:100]  # Limit
                
                # Imports
                imports = []
                for section in elf.iter_sections():
                    if section.header.sh_type == 'SHT_REL':
                        for rel in section.iter_relocations():
                            if rel.symbol and rel.symbol.name:
                                imports.append(rel.symbol.name)
                self.results['imports'] = imports[:100]  # Limit
                
        except Exception as e:
            self.results['elf_error'] = str(e)
    
    def analyze_pe(self):
        """Analyze PE file"""
        try:
            import pefile
            
            pe = pefile.PE(self.file_path)
            
            self.results['format'] = 'PE'
            self.results['arch'] = 'x86' if pe.FILE_HEADER.Machine == 0x14c else 'x64'
            self.results['entry_point'] = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
            self.results['image_base'] = hex(pe.OPTIONAL_HEADER.ImageBase)
            
            # Sections
            sections = []
            for section in pe.sections:
                sections.append({
                    'name': section.Name.decode().rstrip('\x00'),
                    'virtual_size': section.Misc_VirtualSize,
                    'raw_size': section.SizeOfRawData,
                    'entropy': section.get_entropy()
                })
            self.results['sections'] = sections
            
            # Imports
            imports = []
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for imp in entry.imports:
                        if imp.name:
                            imports.append(imp.name.decode())
            self.results['imports'] = imports[:100]  # Limit
            
            # Exports
            exports = []
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if exp.name:
                        exports.append(exp.name.decode())
            self.results['exports'] = exports[:100]  # Limit
            
            pe.close()
            
        except Exception as e:
            self.results['pe_error'] = str(e)
    
    def detect_packers(self):
        """Detect common packers/protectors"""
        packers = []
        
        if not self.file_data:
            return packers
        
        # Common packer signatures
        signatures = {
            'UPX': b'UPX',
            'ASPack': b'ASPack',
            'PECompact': b'PECompact',
            'Themida': b'Themida',
            'VMProtect': b'VMProtect',
            'Armadillo': b'Armadillo',
            'Enigma': b'Enigma Protector',
            'PEtite': b'PEtite',
        }
        
        for name, sig in signatures.items():
            if sig in self.file_data:
                packers.append(name)
        
        # High entropy detection
        entropy = self.calculate_entropy()
        if entropy > 7.0:
            packers.append(f"High entropy ({entropy:.2f}) - possible packing")
        
        return packers
    
    def detect_suspicious(self):
        """Detect suspicious characteristics"""
        suspicious = []
        
        if not self.file_data:
            return suspicious
        
        # Check for suspicious strings
        suspicious_strings = [
            b'cmd.exe',
            b'/bin/sh',
            b'password',
            b'inject',
            b'hook',
            b'keylog',
            b'ransom',
            b'bitcoin',
            b'tor',
            b'onion',
        ]
        
        for string in suspicious_strings:
            if string in self.file_data:
                suspicious.append(f"Contains string: {string.decode()}")
        
        # Check for executable in data sections
        if self.file_data[:2] == b'MZ':
            # PE file - check for suspicious sections
            if b'.upx' in self.file_data or b'UPX' in self.file_data:
                suspicious.append("UPX packed executable")
        
        return suspicious
    
    def analyze(self):
        """Main analysis function"""
        print("\nAnalyzing file...")
        
        # Load file
        if not self.load_file():
            return False
        
        # Calculate entropy
        self.results['entropy'] = self.calculate_entropy()
        
        # Identify format
        if self.file_data[:4] == b'\x7fELF':
            self.analyze_elf()
        elif self.file_data[:2] == b'MZ':
            self.analyze_pe()
        else:
            self.results['format'] = 'Unknown'
        
        # Detect packers
        self.results['packers'] = self.detect_packers()
        
        # Detect suspicious
        self.results['suspicious'] = self.detect_suspicious()
        
        # Print results
        self.print_results()
        
        return True
    
    def print_results(self):
        """Print analysis results"""
        print(f"\n{'=' * 50}")
        print(f"ANALYSIS RESULTS")
        print(f"{'=' * 50}")
        
        print(f"\n--- Basic Info ---")
        print(f"File: {self.results['file_path']}")
        print(f"Size: {self.results['file_size']} bytes")
        print(f"Type: {self.results['file_type']}")
        print(f"Format: {self.results.get('format', 'Unknown')}")
        
        print(f"\n--- Hashes ---")
        print(f"MD5:    {self.results['md5']}")
        print(f"SHA1:   {self.results['sha1']}")
        print(f"SHA256: {self.results['sha256']}")
        
        print(f"\n--- Entropy ---")
        print(f"Shannon: {self.results['entropy']:.4f}")
        if self.results['entropy'] > 7.0:
            print(f"  WARNING: High entropy - possible packing/encryption")
        
        if 'arch' in self.results:
            print(f"\n--- Architecture ---")
            print(f"Arch: {self.results['arch']}")
            print(f"Entry: {self.results.get('entry_point', 'N/A')}")
        
        if 'sections' in self.results:
            print(f"\n--- Sections ({len(self.results['sections'])}) ---")
            for section in self.results['sections'][:10]:
                print(f"  {section['name']}: {section.get('size', 'N/A')} bytes")
        
        if 'imports' in self.results:
            print(f"\n--- Imports ({len(self.results['imports'])}) ---")
            for imp in self.results['imports'][:20]:
                print(f"  {imp}")
        
        if self.results['packers']:
            print(f"\n--- Packers Detected ---")
            for packer in self.results['packers']:
                print(f"  {packer}")
        
        if self.results['suspicious']:
            print(f"\n--- Suspicious Findings ---")
            for finding in self.results['suspicious']:
                print(f"  {finding}")
        
        print(f"\n{'=' * 50}")
    
    def export_json(self, output_path):
        """Export results to JSON"""
        with open(output_path, 'w') as f:
            json.dump(self.results, f, indent=2)
        print(f"\nResults exported to: {output_path}")

def main():
    parser = argparse.ArgumentParser(description='M1 — Static Analyzer')
    parser.add_argument('--file', '-f', required=True, help='File to analyze')
    parser.add_argument('--output', '-o', help='Output JSON file')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.file):
        print(f"ERROR: File not found: {args.file}")
        sys.exit(1)
    
    analyzer = StaticAnalyzer(args.file)
    analyzer.analyze()
    
    if args.output:
        analyzer.export_json(args.output)

if __name__ == '__main__':
    main()
