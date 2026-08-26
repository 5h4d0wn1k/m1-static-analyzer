# M1 — Static Analyzer

ELF/PE static analysis tool for malware research.

## Overview

This project implements a static analysis tool that:
- Parses ELF and PE file formats
- Extracts imports, exports, sections
- Detects common packers/protectors
- Calculates Shannon entropy
- Identifies suspicious characteristics

## Features

- **File format support**: ELF and PE executables
- **Section analysis**: Extract and analyze code sections
- **Import/Export extraction**: Identify linked libraries
- **Packer detection**: Detect UPX, Themida, VMProtect, etc.
- **Entropy calculation**: Identify packed/encrypted sections
- **Suspicious string detection**: Find malware indicators

## Installation

```bash
pip install python-magic pefile pyelftools
```

## Usage

```bash
# Analyze file
python3 static_analyzer.py --file suspicious.exe

# Export to JSON
python3 static_analyzer.py --file malware.elf --output results.json
```

## Example Output

```
=== M1 — Static Analyzer ===
File: suspicious.exe

==================================================
ANALYSIS RESULTS
==================================================

--- Basic Info ---
File: suspicious.exe
Size: 123456 bytes
Type: PE32+ executable (GUI) x86-64
Format: PE

--- Hashes ---
MD5:    5f4dcc3b5aa765d61d8327deb882cf99
SHA1:   5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8
SHA256: 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8

--- Entropy ---
Shannon: 6.8432

--- Sections (5) ---
  .text: 45678 bytes
  .data: 12345 bytes
  .rdata: 8901 bytes

--- Imports (42) ---
  kernel32.dll
  user32.dll
  advapi32.dll

==================================================
```

## Legal Disclaimer

**IMPORTANT: Read before use.**

This project is provided for **educational and authorized security testing purposes only**. 

### Authorization Requirements
- You MUST have explicit written permission before analyzing files
- Unauthorized analysis of malware may violate computer crime laws
- This tool should ONLY be used on files you own or have written authorization to analyze

### Legal Framework
- **Computer Fraud and Abuse Act (CFAA)**: Unauthorized access to computer systems is a federal crime
- **Malware Distribution Laws**: Distributing malware analysis tools may be regulated
- **State Laws**: Many states have additional computer crime statutes
- **Export Controls**: Some analysis tools may be subject to export controls

### Acceptable Use
- Analyzing your own software
- Authorized malware analysis with written scope
- Academic research in controlled lab environments
- Security education and training

### Prohibited Use
- Analyzing malware without authorization
- Reverse engineering proprietary software without permission
- Any activity that violates applicable laws or regulations
- Commercial use without proper licensing

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is not responsible for any misuse or damage caused by this software.

### Responsible Disclosure
If you discover vulnerabilities using this tool, follow responsible disclosure practices:
1. Report to the vendor/owner privately
2. Allow reasonable time for remediation
3. Do not exploit beyond proof of concept

## License

MIT
