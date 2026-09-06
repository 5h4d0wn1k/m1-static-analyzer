# M1 — Static Analyzer

Hand-written ELF / PE structural parser for malware research and
reverse-engineering education.

## What genuinely works

Parses **REAL file formats** with its own pure-Python parsers (no `pefile`,
`pyelftools`, or `python-magic` dependencies):

- **ELF 32/64** — magic, ELF header (type/machine/entry), section headers,
  section entropy, symbol tables (`.symtab`/`.dynsym`), and **dynamic imports**
  recovered from GOT/PLT relocation entries (`.rela.plt`/`.rel.plt`, `GLOB_DAT`,
  `JUMP_SLOT`, `COPY`) plus unresolved `.dynsym` function symbols.
- **PE (MZ → COFF → Optional → sections → import/export)** — DOS header,
  COFF header (machine, sections, characteristics), Optional header
  (PE32/PE32+, image base, entry point, subsystem), section headers with
  flags + entropy, **import table** (per-DLL function lists via RVA→offset
  mapping) and **export table**.
- **Strings**, **Shannon entropy**, **packer hints** (UPX, Themida, VMProtect,
  ASPack, PECompact, …), and **dangerous API** detection correlated against
  the parsed import table.

## Real fixtures shipped

| Fixture | What it is |
|---------|-----------|
| `fixtures/hello_elf` | Real ELF64 executable compiled with `gcc` (calls `printf`, `strncpy`) |
| `fixtures/sample_pe32.exe` | Handcrafted but spec-valid PE32 image with a KERNEL32.dll import table (`CreateFileA`, `LoadLibraryA`) |

The bare-metal PE fixture is built byte-by-byte per the MS PE/COFF spec by
`firmware/build_pe_fixture.py`.

## Usage

```bash
# Help
python3 firmware/static_analyzer.py --help

# Analyze a real ELF (compiled sample)
python3 firmware/static_analyzer.py -f fixtures/hello_elf

# Analyze the handcrafted PE and dump JSON
python3 firmware/static_analyzer.py -f fixtures/sample_pe32.exe -o reports/sample.json

# Also emit Markdown
python3 firmware/static_analyzer.py -f fixtures/hello_elf --markdown -o reports/hello.json
```

### Offline demo (exits 0)

```bash
python3 firmware/static_analyzer.py -f fixtures/hello_elf -o reports/hello.json
python3 firmware/static_analyzer.py -f fixtures/sample_pe32.exe -o reports/sample.json
```

## Tests

```bash
python3 -m unittest discover -s tests -v
```

Runs fully offline against the shipped fixtures and a PE built on the fly in a
temp dir.

## Live Lab Test Plan

1. In an isolated VM/container run the offline demo; confirm exit code 0 and
   that JSON lists real ELF sections/imports and PE imports.
2. Point the tool at a genuine unknown sample you own or have authorization to
   analyze; confirm the parser identifies ELF vs PE and reports sections,
   entropy, imports, packer hints.
3. Cross-check imports against `objdump -p` (ELF) / any PE viewer; entries
   should agree.
4. Only ever analyze files you own or have explicit written authorization for.

## Metrics

- Format parser: ELF32/ELF64 + PE32/PE32+ headers, sections, symbols,
  relocations/imports, exports.
- Test count: 13 stdlib unittest cases (see `tests/`).
- Dependencies: Python 3 stdlib only (`struct`, `hashlib`, `math`, `json`,
  `argparse`).
- Offline demo verifies both a real gcc-compiled ELF and a handcrafted PE.

## IMPORTANT: Read before use.

This tool is for **educational and authorized analysis only**. You MUST have
explicit written permission to analyze any file. Only analyze files you own or
are authorized to inspect. Unauthorized analysis of malware or software may
violate computer-crime laws. The author is not responsible for misuse.

## License

MIT — see `LICENSE`.
