#!/usr/bin/env python3
"""
M1 — Static Analyzer
Hand-written ELF / PE structural parser for malware research.

Parses REAL file formats with own pure-Python parsers (no external
pefile / pyelftools / python-magic):
  - ELF 32/64 headers, program headers, section headers,
    symbol tables (.symtab/.dynsym), dynamic imports (GOT/PLT relocations)
  - PE (MZ -> COFF -> Optional header -> sections -> import/export tables)
  - strings, section entropy, packer hints, dangerous API detection

Usage:
    python3 static_analyzer.py --file <binary> [--output report.json] [--markdown]

WARNING: Educational / authorized analysis only.
"""

import argparse
import hashlib
import json
import math
import os
import re
import struct
import sys
from collections import Counter

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def read_ascii(data, offset, maxlen=256):
    """Read a NUL-terminated ASCII string starting at offset, bounded."""
    if offset is None or offset < 0 or offset >= len(data):
        return ""
    end = data.find(b"\x00", offset)
    if end == -1 or end - offset > maxlen:
        end = min(offset + maxlen, len(data))
    return data[offset:end].decode("ascii", errors="replace")


def entropy(data):
    """Shannon entropy in bits/byte."""
    if not data:
        return 0.0
    counter = Counter(data)
    n = len(data)
    ent = 0.0
    for c in counter.values():
        p = c / n
        ent -= p * math.log2(p)
    return ent


def extract_strings(data, min_len=4):
    """Yield (offset, string) for printable ASCII runs."""
    result = []
    current = []
    start = 0
    for i, b in enumerate(data):
        if 32 <= b <= 126:
            if not current:
                start = i
            current.append(chr(b))
        else:
            if len(current) >= min_len:
                result.append((start, "".join(current)))
            current = []
    if len(current) >= min_len:
        result.append((start, "".join(current)))
    return result


# ---------------------------------------------------------------------------
# Dangerous API / packer hints
# ---------------------------------------------------------------------------

DANGEROUS_APIS = {
    "Process": ["CreateProcess", "WinExec", "ShellExecute", "VirtualAlloc",
                "VirtualProtect", "WriteProcessMemory", "CreateRemoteThread",
                "SetWindowsHookEx", "NtUnmapViewOfSection"],
    "File_writes": ["WriteFile", "CreateFile", "DeleteFile", "MoveFile",
                    "CopyFile", "SetFileAttributes"],
    "Network": ["WSAStartup", "socket", "connect", "send", "recv",
                "InternetOpen", "HttpSendRequest", "URLDownloadToFile",
                "WinHttpOpen"],
    "Persistence": ["RegSetValue", "RegCreateKey", "CreateService",
                    "StartService", "RegOpenKey"],
}

PACKER_SIGNATURES = {
    "UPX": [b"UPX0", b"UPX1", b"UPX!"],
    "Themida/WinLicense": [b"Themida", b"WinLicense"],
    "VMProtect": [b"VMProtect", b".vmp0", b".vmp1"],
    "ASPack": [b"ASPack"],
    "PECompact": [b"PECompact"],
    "MPRESS": [b"MPRESS"],
    "Armadillo": [b"Armadillo", b".adata"],
    "Enigma Protector": [b"Enigma", b".enigma1"],
    "Obsidium": [b"Obsidium", b".obsidium"],
}


# ---------------------------------------------------------------------------
# ELF parser
# ---------------------------------------------------------------------------

ELFCLASS32 = 1
ELFCLASS64 = 2
ET_TYPES = {0: "NONE", 1: "REL", 2: "EXEC", 3: "DYN", 4: "CORE"}
EM_MACHINES = {0: "NO_MACHINE", 3: "i386 (x86)", 8: "MIPS", 40: "ARM",
               62: "x86_64", 183: "AArch64", 243: "RISC-V"}
SHT_NAMES = {1: "PROGBITS", 2: "SYMTAB", 3: "STRTAB", 4: "RELA",
             5: "HASH", 6: "DYNAMIC", 7: "NOTE", 8: "NOBITS", 9: "REL",
             11: "DYNSYM", 14: "INIT_ARRAY", 15: "FINI_ARRAY"}
R_X86_64 = {0: "R_X86_64_NONE", 1: "R_X86_64_64", 2: "R_X86_64_PC32",
            5: "R_X86_64_COPY", 6: "R_X86_64_GLOB_DAT",
            7: "R_X86_64_JUMP_SLOT", 8: "R_X86_64_RELATIVE",
            9: "R_X86_64_GOTPCREL"}
R_I386 = {0: "R_386_NONE", 1: "R_386_32", 2: "R_386_PC32", 5: "R_386_COPY",
          6: "R_386_GLOB_DAT", 7: "R_386_JUMP_SLOT", 8: "R_386_RELATIVE"}


class ELFParser:
    """Hand-rolled ELF32/64 reader (magic, headers, sections, symbols,
    dynamic imports via GOT/PLT relocations)."""

    def __init__(self, data):
        self.data = data
        self.cls = None
        self.endian = "<"
        self.header = {}
        self.sections = []
        self.symbols = []
        self.imports = set()
        self.exports = []

    def parse(self):
        if len(self.data) < 16 or not self.data.startswith(b"\x7fELF"):
            raise ValueError("Not a valid ELF file")
        self.cls = self.data[4]
        if self.cls not in (ELFCLASS32, ELFCLASS64):
            raise ValueError("Unsupported ELF class: %d" % self.cls)
        self.endian = "<" if self.data[5] == 1 else ">"
        e = self.endian
        if self.cls == ELFCLASS64:
            fields = struct.unpack_from(e + "HHIQQQIHHHHHH", self.data, 16)
            sh_entsize_idx = 10
        else:
            fields = struct.unpack_from(e + "HHIIIIIHHHHHH", self.data, 16)
            sh_entsize_idx = 10
        self.header = {
            "e_type": fields[0], "e_machine": fields[1], "e_version": fields[2],
            "e_entry": fields[3], "e_phoff": fields[4], "e_shoff": fields[5],
            "e_flags": fields[6], "e_ehsize": fields[7], "e_phentsize": fields[8],
            "e_phnum": fields[9], "e_shentsize": fields[10], "e_shnum": fields[11],
            "e_shstrndx": fields[12],
        }
        self._parse_sections()
        self._parse_symbols()
        self._parse_dynamic_imports()
        return self

    def _read_string(self, strtab_off, name_off):
        if strtab_off is None:
            return ""
        return read_ascii(self.data, strtab_off + name_off)

    def _parse_sections(self):
        e = self.endian
        shoff = self.header["e_shoff"]
        shentsize = self.header["e_shentsize"] or (64 if self.cls == 64 else 40)
        shnum = self.header["e_shnum"]
        fmt = "IIQQQQIIQQ" if self.cls == ELFCLASS64 else "IIIIIIIIII"
        sections = []
        for i in range(shnum):
            off = shoff + i * shentsize
            if off + struct.calcsize(fmt) > len(self.data):
                break
            v = struct.unpack_from(e + fmt, self.data, off)
            sections.append({
                "index": i, "sh_name": v[0], "sh_type": v[1],
                "sh_flags": v[2], "sh_addr": v[3], "sh_offset": v[4],
                "sh_size": v[5], "sh_link": v[6], "sh_info": v[7],
                "sh_addralign": v[8], "sh_entsize": v[9],
            })
        # resolve names
        shstrndx = self.header["e_shstrndx"]
        shstr_off = None
        if shstrndx < len(sections):
            shstr_off = sections[shstrndx]["sh_offset"]
        for s in sections:
            s["name"] = self._read_string(shstr_off, s["sh_name"]) or "[%d]" % s["index"]
            raw = self.data[s["sh_offset"]:s["sh_offset"] + s["sh_size"]]
            s["entropy"] = round(entropy(raw), 4)
        self.sections = sections

    def _parse_symbols(self):
        e = self.endian
        for s in self.sections:
            if s["sh_type"] not in (2, 11):
                continue
            entsize = s["sh_entsize"] or (24 if self.cls == ELFCLASS64 else 16)
            count = s["sh_size"] // entsize if entsize else 0
            strtab_off = None
            if s["sh_link"] < len(self.sections):
                strtab_off = self.sections[s["sh_link"]]["sh_offset"]
            for i in range(count):
                off = s["sh_offset"] + i * entsize
                if off + entsize > len(self.data):
                    break
                if self.cls == ELFCLASS64:
                    st_name, st_info, st_other, st_shndx, st_value, st_size = \
                        struct.unpack_from(e + "IBBHQQ", self.data, off)
                else:
                    st_name, st_value, st_size, st_info, st_other, st_shndx = \
                        struct.unpack_from(e + "IIIBBH", self.data, off)
                bind = (st_info >> 4) & 0xF
                typ = st_info & 0xF
                name = self._read_string(strtab_off, st_name)
                if bind == 1 and typ == 2:  # GLOBAL FUNC
                    self.exports.append(name)
                self.symbols.append({
                    "name": name, "bind": bind, "type": typ,
                    "value": st_value, "size": st_size, "shndx": st_shndx,
                })

    def _parse_dynamic_imports(self):
        """Extract imported function names from .rela.plt/.rel.plt (GOT/PLT)
        and .dynsym symbol table bound to undefined (SHN_UNDEF, shndx==0)."""
        e = self.endian
        for s in self.sections:
            if s["sh_type"] not in (4, 9):  # RELA / REL
                continue
            strtab_off = None
            if s["sh_link"] < len(self.sections):
                strtab_off = self.sections[s["sh_link"]]["sh_offset"]
            entsize = s["sh_entsize"] or (24 if self.cls == ELFCLASS64 else 16)
            count = s["sh_size"] // entsize if entsize else 0
            rtype_mask = 0xFF if self.cls == ELFCLASS64 else 0xFF
            reloc_map = R_X86_64 if self.header["e_machine"] == 62 else R_I386
            for i in range(count):
                off = s["sh_offset"] + i * entsize
                if off + entsize > len(self.data):
                    break
                if self.cls == ELFCLASS64:
                    r_offset, r_info, r_addend = struct.unpack_from(e + "QQq", self.data, off)
                else:
                    r_offset, r_info, r_addend = struct.unpack_from(e + "IIi", self.data, off)
                typ = r_info & rtype_mask
                if typ not in (reloc_map and {1, 2, 5, 6, 7} or {1, 2, 5, 6, 7}):
                    continue
                if self.cls == ELFCLASS64:
                    if typ in (6, 7, 5):  # GLOB_DAT / JUMP_SLOT / COPY
                        symndx = r_info >> 32
                        func = self._symbol_name(symndx, strtab_off)
                        if func:
                            self.imports.add(func)
                else:
                    if typ in (6, 7, 5):
                        symndx = r_info >> 8
                        func = self._symbol_name(symndx, strtab_off)
                        if func:
                            self.imports.add(func)
        # Also add unresolved dynsym symbols
        for s in self.sections:
            if s["sh_type"] != 11:
                continue
            entsize = s["sh_entsize"] or (24 if self.cls == ELFCLASS64 else 16)
            count = s["sh_size"] // entsize if entsize else 0
            strtab_off = None
            if s["sh_link"] < len(self.sections):
                strtab_off = self.sections[s["sh_link"]]["sh_offset"]
            for i in range(count):
                off = s["sh_offset"] + i * entsize
                if off + entsize > len(self.data):
                    break
                if self.cls == ELFCLASS64:
                    st_name, st_info, st_other, st_shndx, st_value, st_size = \
                        struct.unpack_from(e + "IBBHQQ", self.data, off)
                else:
                    st_name, st_value, st_size, st_info, st_other, st_shndx = \
                        struct.unpack_from(e + "IIIBBH", self.data, off)
                typ = st_info & 0xF
                if st_shndx == 0 and typ == 2:
                    name = self._read_string(strtab_off, st_name)
                    if name:
                        self.imports.add(name)

    def _symbol_name(self, symndx, strtab_off):
        if symndx >= len(self.symbols):
            return ""
        name = self.symbols[symndx]["name"]
        return name

    def summary(self):
        return {
            "format": "ELF",
            "class": "ELF%d" % (64 if self.cls == ELFCLASS64 else 32),
            "endian": "little" if self.endian == "<" else "big",
            "type": ET_TYPES.get(self.header["e_type"], "UNKNOWN"),
            "machine": EM_MACHINES.get(self.header["e_machine"],
                                       hex(self.header["e_machine"])),
            "entry_point": "0x%x" % self.header["e_entry"],
            "sections": [
                {"name": s["name"], "type": SHT_NAMES.get(s["sh_type"], str(s["sh_type"])),
                 "addr": hex(s["sh_addr"]), "size": s["sh_size"],
                 "entropy": s["entropy"]}
                for s in self.sections
            ],
            "imports": sorted(self.imports),
            "exports": list(dict.fromkeys(self.exports)),
        }


# ---------------------------------------------------------------------------
# PE parser
# ---------------------------------------------------------------------------

IMAGE_DOS_SIGNATURE = 0x5A4D
IMAGE_NT_SIGNATURE = 0x00004550
MACHINE_TYPES = {0x014c: "I386", 0x8664: "AMD64", 0x01c0: "ARM", 0xaa64: "ARM64"}
CHARACTERISTICS = {0x0002: "EXECUTABLE_IMAGE", 0x0020: "LARGE_ADDRESS_AWARE",
                   0x0100: "32BIT_MACHINE", 0x2000: "DLL"}
SUBSYSTEMS = {1: "NATIVE", 2: "WINDOWS_GUI", 3: "WINDOWS_CUI"}


class PEParser:
    """Hand-rolled PE reader (DOS stub -> COFF -> Optional -> sections ->
    imports -> exports)."""

    def __init__(self, data):
        self.data = data
        self.dos = {}
        self.file_header = {}
        self.optional = {}
        self.sections = []
        self.imports = []
        self.exports = []
        self.arch = None
        self.image_base = 0

    def parse(self):
        if len(self.data) < 0x40:
            raise ValueError("File too small to be a PE")
        sig = struct.unpack_from("<H", self.data, 0)[0]
        if sig != IMAGE_DOS_SIGNATURE:
            raise ValueError("Bad DOS signature")
        self.dos["e_magic"] = hex(sig)
        e_lfanew = struct.unpack_from("<I", self.data, 0x3c)[0]
        self.dos["e_lfanew"] = e_lfanew
        if e_lfanew + 24 > len(self.data):
            raise ValueError("NT header out of range")
        nt = struct.unpack_from("<I", self.data, e_lfanew)[0]
        if nt != IMAGE_NT_SIGNATURE:
            raise ValueError("Bad PE signature")
        coff = e_lfanew + 4
        machine, nsec, ts, psym, nsym, optsize, chars = \
            struct.unpack_from("<HHIIIHH", self.data, coff)
        self.file_header = {
            "machine": machine,
            "machine_name": MACHINE_TYPES.get(machine, hex(machine)),
            "number_of_sections": nsec,
            "timestamp": ts,
            "characteristics": chars,
            "characteristics_flags": [v for k, v in CHARACTERISTICS.items() if chars & k],
            "size_of_optional_header": optsize,
        }
        opt_offset = coff + 20
        magic = struct.unpack_from("<H", self.data, opt_offset)[0]
        self.arch = "PE32" if magic == 0x10B else "PE32+" if magic == 0x20B else None
        if self.arch is None:
            raise ValueError("Unsupported optional header magic")
        self._parse_optional(opt_offset, magic)
        self._parse_sections(opt_offset)
        self._parse_imports(opt_offset)
        self._parse_exports(opt_offset)
        return self

    def _parse_optional(self, opt_offset, magic):
        if magic == 0x20B:  # PE32+
            fmt = "<HBBIIIIIIIIIIHHIIIIQHIIIIIIII"
            s = struct.calcsize(fmt)
            v = struct.unpack_from(fmt, self.data, opt_offset)
            self.image_base = v[9]
            self.optional = {
                "magic": "PE32+", "major_linker": v[1], "minor_linker": v[2],
                "address_of_entry_point": hex(v[6]), "image_base": hex(v[9]),
                "size_of_image": v[18], "subsystem": v[21],
                "number_of_rva_and_sizes": v[22],
                "data_directories_offset": opt_offset + s,
            }
        else:  # PE32
            fmt = "<HBBIIIIIIIIIIHHIIIIHHIIIIIIII"
            s = struct.calcsize(fmt)
            v = struct.unpack_from(fmt, self.data, opt_offset)
            self.image_base = v[9]
            self.optional = {
                "magic": "PE32", "major_linker": v[1], "minor_linker": v[2],
                "address_of_entry_point": hex(v[6]), "image_base": hex(v[9]),
                "size_of_image": v[18], "subsystem": v[21],
                "number_of_rva_and_sizes": v[22],
                "data_directories_offset": opt_offset + s,
            }

    def _parse_sections(self, opt_offset):
        n = self.file_header["number_of_sections"]
        sec_off = opt_offset + self.file_header["size_of_optional_header"]
        for i in range(n):
            off = sec_off + i * 40
            if off + 40 > len(self.data):
                break
            name = read_ascii(self.data, off, 8).rstrip("\x00")
            vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", self.data, off + 8)
            chars = struct.unpack_from("<I", self.data, off + 36)[0]
            raw = self.data[rawptr:rawptr + rawsize]
            self.sections.append({
                "name": name, "virtual_size": vsize, "virtual_address": vaddr,
                "raw_size": rawsize, "raw_offset": rawptr,
                "characteristics": chars,
                "flags": self._section_flags(chars),
                "entropy": round(entropy(raw), 4),
            })

    def _section_flags(self, chars):
        flags = []
        if chars & 0x20000000:
            flags.append("EXECUTE")
        if chars & 0x40000000:
            flags.append("READ")
        if chars & 0x80000000:
            flags.append("WRITE")
        if chars & 0x00000020:
            flags.append("CODE")
        if chars & 0x00000040:
            flags.append("DATA")
        return flags

    def _rva_to_offset(self, rva):
        for s in self.sections:
            if s["virtual_address"] <= rva < s["virtual_address"] + max(s["virtual_size"], s["raw_size"]):
                return s["raw_offset"] + (rva - s["virtual_address"])
        return None

    def _dd(self, opt_offset, index):
        # data directory offset: PE32 optional ends at +96, each dir 8 bytes
        base = opt_offset + 96 if self.arch == "PE32" else opt_offset + 112
        off = base + index * 8
        if off + 8 <= len(self.data):
            rva, size = struct.unpack_from("<II", self.data, off)
            return rva, size
        return 0, 0

    def _parse_imports(self, opt_offset):
        rva, size = self._dd(opt_offset, 1)  # import table
        if not rva:
            return
        off = self._rva_to_offset(rva)
        for _ in range(512):
            if off is None or off + 20 > len(self.data):
                break
            olt, time, fwd, name_rva, iat = struct.unpack_from("<IIIII", self.data, off)
            if olt == 0 and name_rva == 0:
                break
            name_off = self._rva_to_offset(name_rva)
            dll = read_ascii(self.data, name_off) if name_off else ""
            funcs = self._read_import_functions(olt)
            self.imports.append({"dll": dll, "functions": funcs})
            off += 20

    def _read_import_functions(self, thunk_rva):
        off = self._rva_to_offset(thunk_rva)
        if off is None:
            return []
        funcs = []
        step = 8 if self.arch == "PE32+" else 4
        for _ in range(2000):
            if off + step > len(self.data):
                break
            if self.arch == "PE32+":
                val = struct.unpack_from("<Q", self.data, off)[0]
                is_ord = (val & 0x8000000000000000) != 0
            else:
                val = struct.unpack_from("<I", self.data, off)[0]
                is_ord = (val & 0x80000000) != 0
            if val == 0:
                break
            if is_ord:
                funcs.append("ord_%d" % (val & 0xFFFF))
            else:
                addr = (val & 0xFFFFFFFF) if self.arch == "PE32+" else val
                hint_off = self._rva_to_offset(addr)
                if hint_off is not None:
                    funcs.append(read_ascii(self.data, hint_off + 2))
            off += step
        return funcs

    def _parse_exports(self, opt_offset):
        rva, size = self._dd(opt_offset, 0)
        if not rva:
            return
        off = self._rva_to_offset(rva)
        if off is None or off + 40 > len(self.data):
            return
        _, _, _, _, n_funcs, n_names, addr_rva, name_rva, ord_rva = \
            struct.unpack_from("<IIIIIIIII", self.data, off)
        name_off = self._rva_to_offset(name_rva)
        for i in range(min(n_names, 1000)):
            e = self._rva_to_offset(name_rva + 4 * i)
            if e is None or e + 4 > len(self.data):
                break
            str_rva = struct.unpack_from("<I", self.data, e)[0]
            so = self._rva_to_offset(str_rva)
            name = read_ascii(self.data, so) if so else ""
            if name:
                self.exports.append(name)

    def summary(self):
        return {
            "format": "PE",
            "architecture": self.arch,
            "machine": self.file_header["machine_name"],
            "entry_point": self.optional["address_of_entry_point"],
            "image_base": self.optional["image_base"],
            "subsystem": SUBSYSTEMS.get(self.optional["subsystem"],
                                        str(self.optional["subsystem"])),
            "sections": [
                {"name": s["name"], "virtual_address": hex(s["virtual_address"]),
                 "virtual_size": s["virtual_size"], "raw_size": s["raw_size"],
                 "flags": s["flags"], "entropy": s["entropy"]}
                for s in self.sections
            ],
            "imports": [
                {"dll": imp["dll"], "functions": imp["functions"]}
                for imp in self.imports
            ],
            "exports": self.exports,
        }


# ---------------------------------------------------------------------------
# Static Analyzer orchestrator
# ---------------------------------------------------------------------------


class StaticAnalyzer:
    def __init__(self, file_path):
        self.file_path = file_path
        with open(file_path, "rb") as f:
            self.data = f.read()
        self.results = self._base()

    def _base(self):
        h = hashlib
        return {
            "file_path": self.file_path,
            "file_size": len(self.data),
            "md5": h.md5(self.data).hexdigest(),
            "sha1": h.sha1(self.data).hexdigest(),
            "sha256": h.sha256(self.data).hexdigest(),
            "file_entropy": round(entropy(self.data), 4),
        }

    def identify_format(self):
        if self.data[:4] == b"\x7fELF":
            return "ELF"
        if self.data[:2] == b"MZ":
            return "PE"
        return None

    def analyze(self):
        self.results["packers"] = self.detect_packers()
        self.results["dangerous_apis"] = self.detect_dangerous()
        self.results["strings"] = [s for _, s in
                                   extract_strings(self.data) if len(s) >= 8][:200]
        fmt = self.identify_format()
        self.results["format"] = fmt
        if fmt == "ELF":
            try:
                self.elf = ELFParser(self.data).parse()
                self.results.update(self.elf.summary())
                self.results["parser"] = "handwritten-ELF"
            except ValueError as e:
                self.results["error"] = str(e)
        elif fmt == "PE":
            try:
                self.pe = PEParser(self.data).parse()
                self.results.update(self.pe.summary())
                self.results["parser"] = "handwritten-PE"
            except ValueError as e:
                self.results["error"] = str(e)
        return self.results

    def detect_packers(self):
        found = []
        for name, sigs in PACKER_SIGNATURES.items():
            for sig in sigs:
                if sig in self.data:
                    found.append(name)
                    break
        return list(dict.fromkeys(found))

    def detect_dangerous(self):
        detected = []
        all_import_names = set()
        if hasattr(self, "elf"):
            all_import_names = set(self.elf.imports)
        elif hasattr(self, "pe"):
            for imp in self.pe.imports:
                all_import_names.update(imp["functions"])
        for cat, apis in DANGEROUS_APIS.items():
            for api in apis:
                if api.encode() in self.data:
                    detected.append({"api": api, "category": cat,
                                     "imported": api in all_import_names})
        return detected

    def to_dict(self):
        return self.results


def build_report(analyzer, fmt="json", markdown=False):
    r = analyzer.to_dict()
    if fmt == "json":
        return json.dumps(r, indent=2)
    if markdown:
        lines = ["# M1 Static Analysis Report",
                 "", "**File:** `%s`  " % r["file_path"],
                 "**Size:** %d bytes  " % r["file_size"],
                 "**Format:** %s  " % r.get("format"),
                 "**SHA256:** `%s`  " % r["sha256"],
                 "", "## Packer hints",
                 ""]
        for p in r.get("packers", []):
            lines.append("- %s" % p)
        lines += ["", "## Section entropy", ""]
        for s in r.get("sections", []):
            lines.append("- `%s`: entropy=%.4f size=%d" %
                         (s.get("name"), s.get("entropy"), s.get("size", s.get("raw_size", 0))))
        lines += ["", "## Imports", ""]
        imports = r.get("imports", [])
        if isinstance(imports, list) and imports and isinstance(imports[0], dict):
            for imp in imports:
                lines.append("- **%s**: %s" % (imp["dll"], ", ".join(imp["functions"][:15])))
        else:
            for imp in imports:
                lines.append("- %s" % imp)
        lines += ["", "## Dangerous APIs", ""]
        for d in r.get("dangerous_apis", []):
            lines.append("- `%s` (%s, imported=%s)" %
                         (d["api"], d["category"], d["imported"]))
        return "\n".join(lines)
    return str(r)


def main():
    parser = argparse.ArgumentParser(
        description="M1 — Static Analyzer (hand-written ELF/PE parser)")
    parser.add_argument("--file", "-f", required=True, help="File to analyze")
    parser.add_argument("--output", "-o", help="Write JSON report to path")
    parser.add_argument("--markdown", action="store_true",
                        help="Also emit a Markdown report")
    args = parser.parse_args()

    if not os.path.exists(args.file):
        print("Error: file not found: %s" % args.file)
        return 1
    try:
        analyzer = StaticAnalyzer(args.file)
        analyzer.analyze()
        report = build_report(analyzer, fmt="json")
        print(report)
        if args.output:
            os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
            with open(args.output, "w") as f:
                f.write(report)
            print("\nJSON report written to %s" % args.output)
        if args.markdown:
            md = build_report(analyzer, fmt="markdown")
            md_path = (args.output + ".md" if args.output
                       else os.path.join("reports", "report.md"))
            os.makedirs(os.path.dirname(os.path.abspath(md_path)), exist_ok=True)
            with open(md_path, "w") as f:
                f.write(md)
            print("Markdown report written to %s" % md_path)
        return 0
    except Exception as e:
        print("Error: %s" % e)
        return 1


if __name__ == "__main__":
    sys.exit(main())
