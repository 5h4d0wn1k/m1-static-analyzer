"""Tests for the M1 hand-written ELF/PE static analyzer.

Runs offline against real fixtures:
  - fixtures/hello_elf : a real ELF64 compiled by gcc (if present)
  - fixtures/sample_pe32.exe : a handcrafted but valid PE32 import-image

Tests build their own PE fixture in a temp dir so the suite is self
contained and deterministic.
"""

import json
import os
import struct
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(REPO, "firmware"))
sys.path.insert(0, REPO)

from static_analyzer import (  # noqa: E402
    StaticAnalyzer,
    ELFParser,
    PEParser,
    entropy,
    extract_strings,
)
import build_pe_fixture  # noqa: E402

FIXTURES = os.path.join(REPO, "fixtures")
HELLO_ELF = os.path.join(FIXTURES, "hello_elf")
PE_FIXTURE = os.path.join(FIXTURES, "sample_pe32.exe")


def build_pe(tmpdir):
    path = os.path.join(tmpdir, "sample.exe")
    with open(path, "wb") as f:
        f.write(build_pe_fixture.build_pe32())
    return path


class TestPEBuilder(unittest.TestCase):
    def test_dos_signature(self):
        data = build_pe_fixture.build_pe32()
        self.assertEqual(struct.unpack_from("<H", data, 0)[0], 0x5A4D)
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        self.assertEqual(struct.unpack_from("<I", data, e_lfanew)[0], 0x00004550)

    def test_optional_header_size_224(self):
        data = build_pe_fixture.build_pe32()
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        optsize = struct.unpack_from("<H", data, e_lfanew + 4 + 16)[0]
        self.assertEqual(optsize, 224)


class TestELFParser(unittest.TestCase):
    def test_parse_real_elf(self):
        if not os.path.exists(HELLO_ELF):
            self.skipTest("gcc fixture not present")
        rel = ELFParser(open(HELLO_ELF, "rb").read()).parse()
        self.assertEqual(rel.summary()["format"], "ELF")
        self.assertEqual(rel.cls, 2)  # ELF64

    def test_imports_from_real_elf(self):
        if not os.path.exists(HELLO_ELF):
            self.skipTest("gcc fixture not present")
        rel = ELFParser(open(HELLO_ELF, "rb").read()).parse()
        # The compiled sample calls printf and strncpy from libc
        self.assertIn("printf", rel.imports)
        self.assertIn("strncpy", rel.imports)

    def test_entries_we_write_ourselves(self):
        # The hello C contains the marker string; ensure extractor sees it
        data = open(HELLO_ELF, "rb").read()
        strings = [s for _, s in extract_strings(data)]
        self.assertTrue(any("password" in s for s in strings))


class TestPEParser(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="m1pe_")
        self.addCleanup(lambda: __import__("shutil").rmtree(self.tmp))

    def test_parse_fixture(self):
        path = build_pe(self.tmp)
        pe = PEParser(open(path, "rb").read()).parse()
        self.assertEqual(pe.summary()["format"], "PE")
        self.assertEqual(pe.arch, "PE32")

    def test_imports_fixture(self):
        path = build_pe(self.tmp)
        pe = PEParser(open(path, "rb").read()).parse()
        dll_names = [imp["dll"] for imp in pe.imports]
        self.assertIn("KERNEL32.dll", dll_names)
        funcs = [f for imp in pe.imports for f in imp["functions"]]
        self.assertIn("CreateFileA", funcs)
        self.assertIn("LoadLibraryA", funcs)

    def test_sections(self):
        path = build_pe(self.tmp)
        pe = PEParser(open(path, "rb").read()).parse()
        names = [s["name"] for s in pe.sections]
        self.assertIn(".text", names)


class TestStaticAnalyzerCLI(unittest.TestCase):
    def _run(self, args):
        return subprocess.run(
            [sys.executable, os.path.join(REPO, "firmware", "static_analyzer.py")] + args,
            capture_output=True, text=True,
        )

    def test_help_exit_zero(self):
        r = self._run(["--help"])
        self.assertEqual(r.returncode, 0)
        self.assertIn("Static Analyzer", r.stdout)

    def test_analyze_gcc_elf_offline(self):
        if not os.path.exists(HELLO_ELF):
            self.skipTest("gcc fixture not present")
        r = self._run(["-f", HELLO_ELF])
        self.assertEqual(r.returncode, 0)
        out = json.loads(r.stdout)
        self.assertEqual(out["format"], "ELF")
        self.assertIn("parser", out)

    def test_analyze_pe_fixture_offline(self):
        d = tempfile.mkdtemp(prefix="m1pe_cli_")
        self.addCleanup(lambda: __import__("shutil").rmtree(d))
        path = build_pe(d)
        r = self._run(["-f", path])
        self.assertEqual(r.returncode, 0)
        out = json.loads(r.stdout)
        self.assertEqual(out["format"], "PE")

    def test_missing_file_exit_1(self):
        r = self._run(["-f", "/nonexistent/xyz.exe"])
        self.assertEqual(r.returncode, 1)


class TestEntropy(unittest.TestCase):
    def test_entropy_range(self):
        self.assertAlmostEqual(entropy(b"\x00" * 100), 0.0, places=3)
        # high entropy random bytes
        import os as _os
        data = _os.urandom(4096)
        self.assertGreater(entropy(data), 7.0)


if __name__ == "__main__":
    unittest.main()
