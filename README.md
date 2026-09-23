> **⚠️ EDUCATIONAL USE ONLY — AUTHORIZED TESTING ONLY.**
> This project exists for education, research, and **defense of systems you own
> or hold explicit written authorization to assess**. Unauthorized use is
> prohibited and may be illegal. Read [ETHICS.md](ETHICS.md) and
> [SCOPE.md](SCOPE.md) before use. Use at your own risk; **AS IS**, no warranty.

# M1 — Static Analyzer

Dependency-free static malware analysis and reverse-engineering research tool that parses
**ELF (32/64) and PE (PE32/PE32+)** files by hand — headers, sections, symbols, imports, exports,
strings, and entropy — to extract indicators from samples you are authorized to analyze.

![MIT](https://img.shields.io/badge/license-MIT-blue.svg)
![GitHub stars](https://img.shields.io/github/stars/5h4d0wn1k/m1-static-analyzer)
![GitHub last commit](https://img.shields.io/github/last-commit/5h4d0wn1k/m1-static-analyzer)
![GitHub issues](https://img.shields.io/github/issues/5h4d0wn1k/m1-static-analyzer)

## Why

Malware analysis starts long before execution: statically examining a suspicious binary’s file
format reveals the imports, sections, and entropy that power triage and attribution. This project is
an educational implementation of real format parsing — no `pefile`, no `pyelftools`, just Python’s
standard library and the ELF/PE specs. Analysts and students studying reverse engineering can trace
how ELF relocations become dynamic imports and how a PE import table maps RVAs to offsets. It is a
malware-research and malware-analysis learning instrument, and it is authorized use only: analyze
files you own or hold written permission to inspect.

## Features

- **ELF 32/64 parsing** — header (type/machine/entry), sections with entropy, `.symtab`/`.dynsym`,
  and dynamic imports recovered from `.rela.plt` / `.rel.plt`, `GLOB_DAT`, `JUMP_SLOT`, `COPY`.
- **PE parsing (MZ → COFF → Optional)** — PE32/PE32+, image base, entry point, subsystem, section
  flags + entropy, per-DLL import tables, and exports.
- **Indicators** — ASCII strings, per-section Shannon entropy, packer hints (UPX, Themida, VMProtect,
  ASPack, PECompact…), and dangerous-API detection correlated against the parsed import table.
- **JSON + Markdown reports** — `--output FILE` writes JSON; `--markdown` also emits a text report.
- **Ships real fixtures** — a gcc-built ELF64 binary and a handcrafted spec-valid PE32 image
  (built byte-by-byte by `firmware/build_pe_fixture.py`).

## Quickstart

Prerequisite: Python 3 (standard library only).

```bash
python3 firmware/static_analyzer.py --help
python3 firmware/static_analyzer.py -f fixtures/hello_elf
python3 firmware/static_analyzer.py -f fixtures/sample_pe32.exe -o reports/sample.json
python3 firmware/static_analyzer.py -f fixtures/hello_elf --markdown -o reports/hello.json
```

## Examples

Real samples shipped with the repo:

- `fixtures/hello_elf` — ELF64 executable compiled with `gcc` (calls `printf`, `strncpy`).
- `fixtures/sample_pe32.exe` — spec-valid PE32 image importing `CreateFileA` and `LoadLibraryA`.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

Runs fully offline against the shipped fixtures plus a PE image built on the fly.

## Project structure

- `firmware/` — `static_analyzer.py` (analyzer) and `build_pe_fixture.py` (fixture builder).
- `fixtures/` — real ELF and PE samples for the demos and tests.
- `tests/` — stdlib unittest suite.

## Documentation

- [CONTRIBUTING.md](CONTRIBUTING.md)
- [SECURITY.md](SECURITY.md)
- [ETHICS.md](ETHICS.md) · [SCOPE.md](SCOPE.md)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Keep the parser dependency-free and the legal gates intact.

## License

MIT — see [LICENSE](LICENSE).