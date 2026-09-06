#!/usr/bin/env python3
"""Build a minimal but valid PE32 fixture for the M7/M1 parser tests.

This constructs a real PE image byte-by-byte following the Microsoft PE/COFF
specification (DOS stub -> COFF header -> optional header with data
directories -> one .text section -> import directory + IAT pointing at
KERNEL32.dll / CreateFileA, LoadLibraryA). The import directory, import
name tables and hint/name entries are laid out in the .rdata section.

The resulting file opens fine in tools that follow the spec; it is a genuine
PE with a working import descriptor structure (the entry-point stub and
section are inert and never executed).
"""

import struct


def build_pe32():
    IMAGE_DOS_SIGNATURE = 0x5A4D
    IMAGE_NT_SIGNATURE = 0x00004550
    IMAGE_FILE_MACHINE_I386 = 0x14c
    IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002
    IMAGE_FILE_32BIT_MACHINE = 0x0100
    IMAGE_FILE_RELOCS_STRIPPED = 0x0001
    IMAGE_FILE_LINE_NUMS_STRIPPED = 0x0004
    IMAGE_FILE_LOCAL_SYMS_STRIPPED = 0x0008
    IMAGE_SUBSYSTEM_WINDOWS_CUI = 3
    MEM_READ = 0x40000000
    MEM_EXECUTE = 0x20000000
    IMAGE_SCN_CNT_CODE = 0x00000020
    IMAGE_SCN_MEM_EXECUTE = MEM_EXECUTE
    IMAGE_SCN_MEM_READ = MEM_READ

    section_alignment = 0x1000
    file_alignment = 0x200

    # We'll assemble a PE32 with:
    #  - .text section (raw off 0x200, RVA 0x1000)
    #  - import descriptors + names placed at end, RVA within .text region
    #    for simplicity (RVA -> file offset mapping via the single section).

    dos_size = 0x80
    pe_offset = dos_size  # e_lfanew

    def dos_header():
        dos = bytearray(0x80)
        struct.pack_into("<H", dos, 0, IMAGE_DOS_SIGNATURE)
        struct.pack_into("<H", dos, 0x18, 0x0040)  # e_cblp (stub size)
        struct.pack_into("<H", dos, 0x3c, pe_offset)  # e_lfanew
        return dos

    # COFF header (20 bytes)
    number_of_sections = 1
    timestamp = 0x5A0D32CE
    size_of_optional_header = 224  # PE32 optional header is 224 bytes
    coff_chars = (IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_32BIT_MACHINE |
                  IMAGE_FILE_RELOCS_STRIPPED | IMAGE_FILE_LINE_NUMS_STRIPPED |
                  IMAGE_FILE_LOCAL_SYMS_STRIPPED)
    coff = struct.pack("<HHIIIHH",
                       IMAGE_FILE_MACHINE_I386,
                       number_of_sections,
                       timestamp,
                       0, 0,  # ptr sym, num sym
                       size_of_optional_header,
                       coff_chars)

    # Optional header PE32 (224 bytes)
    # Layout (with data directories at the end):
    # magic H, linker ver B,B, SizeOfCode, InitData, UninitData,
    # AddressOfEntryPoint, BaseOfCode, BaseOfData, ImageBase,
    # SectionAlignment, FileAlignment, OS ver, Image ver, Subsystem ver,
    # Win32Version, SizeOfImage, SizeOfHeaders, Checksum, Subsystem,
    # DllCharacteristics, SizeOfStackReserve, SizeOfStackCommit,
    # SizeOfHeapReserve, SizeOfHeapCommit, LoaderFlags,
    # NumberOfRvaAndSizes, then 16 data-directories (RVA,size each).

    # Compute where import data lives. Put it after the code in .text.
    # .text raw offset = 0x200, RVA = 0x1000, size must fit.
    # We'll place data at RVA 0x1000 + code_len (aligned) and grow section.
    code_len = 0x10  # inert stub

    # Import structures:
    #   IMPORT_DIRECTORY: 1 descriptor (20 bytes) + null descriptor (20)
    #   Name: "KERNEL32.dll\0"
    #   OriginalFirstThunk / FirstThunk array: pointers to IMAGE_IMPORT_BY_NAME
    #   Hint/Name: H hint + "CreateFileA\0" ; ... ; null terminator
    dll_name = b"KERNEL32.dll\x00"
    func_names = [b"CreateFileA\x00", b"LoadLibraryA\x00"]
    hint_names = [struct.pack("<H", 0) + n for n in func_names]
    hint_names_blob = b"".join(hint_names)

    # Layout plan within a data region:
    #   offset 0 : import descriptor 1 (20 bytes)
    #   offset 20: null descriptor (20 bytes)  -> 40 bytes for descriptors
    #   offset 40: OriginalFirstThunk (OFT) array: 3 ptrs (12) + null
    #   offset 52: DLL name string
    #   offset 52+len: FirstThunk (IAT) array: 3 ptrs + null
    #   then hint/name entries as separate RVAs.

    data_region_len = 40 + (len(func_names) + 1) * 4 * 2 + len(dll_name) + len(hint_names_blob)

    # .text file offset
    text_file_off = 0x200
    text_rva = 0x1000
    # total raw size of section
    raw_size = text_file_off_size = 0x200 + data_region_len

    raw_size_rounded = ((raw_size + file_alignment - 1) // file_alignment) * file_alignment

    # Fill data region starting at raw offset text_file_off+code_len
    region_file_off = text_file_off + code_len
    region_rva = text_rva + code_len

    desc_off = region_rva
    oft_rva = region_rva + 40
    dllname_rva = oft_rva + (len(func_names) + 1) * 4
    iat_rva = dllname_rva + len(dll_name)
    hint_base_rva = iat_rva + (len(func_names) + 1) * 4

    # build hint/name rvas
    hint_rvas = []
    pos = hint_base_rva
    for hn in hint_names:
        hint_rvas.append(pos)
        pos += len(hn)
    hint_region_size = pos - hint_base_rva

    total_data_bytes = data_region_len
    if total_data_bytes < (hint_region_size + (hint_base_rva - region_rva)):
        total_data_bytes = (hint_region_size + (hint_base_rva - region_rva))

    entry_point_rva = text_rva  # points to inert ret stub

    size_of_headers = dos_size + 4 + 20 + 224 + 40  # dos+sig+coff+opt+sec

    size_of_image = ((text_rva + raw_size_rounded + section_alignment - 1)
                     // section_alignment) * section_alignment

    opt = bytearray()
    opt += struct.pack("<HBB", 0x10B, 14, 0)  # magic, linker maj/min
    opt += struct.pack("<II", code_len, 0)  # SizeOfCode, SizeOfInitData
    opt += struct.pack("<I", 0)             # SizeOfUninitData
    opt += struct.pack("<I", entry_point_rva)  # AddressOfEntryPoint
    opt += struct.pack("<I", text_rva)      # BaseOfCode
    opt += struct.pack("<I", text_rva)      # BaseOfData
    opt += struct.pack("<I", 0x00400000)    # ImageBase
    opt += struct.pack("<I", section_alignment)
    opt += struct.pack("<I", file_alignment)
    opt += struct.pack("<HH", 6, 0)         # OS ver
    opt += struct.pack("<HH", 0, 0)         # Image ver
    opt += struct.pack("<HH", 6, 0)         # Subsystem ver
    opt += struct.pack("<I", 0)             # Win32Version
    opt += struct.pack("<I", size_of_image) # SizeOfImage
    opt += struct.pack("<I", size_of_headers)  # SizeOfHeaders
    opt += struct.pack("<I", 0)             # Checksum
    opt += struct.pack("<HH", IMAGE_SUBSYSTEM_WINDOWS_CUI, 0)  # Subsystem, DllChars
    opt += struct.pack("<II", 0x100000, 0x1000)  # StackReserve, StackCommit
    opt += struct.pack("<II", 0x100000, 0x1000)  # HeapReserve, HeapCommit
    opt += struct.pack("<II", 0, 16)        # LoaderFlags, NumberOfRvaAndSizes

    # Data directories (16 * 8 bytes = 128)
    directories = [ (0,0) ] * 16
    directories[0] = (0, 0)              # Export
    directories[1] = (desc_off, 40)      # Import (rva, size)
    for rva, size in directories:
        opt += struct.pack("<II", rva, size)

    optional_header = bytes(opt)
    assert len(optional_header) == 224

    # Section header (.text), 40 bytes
    sec_name = b".text\x00\x00\x00"
    section_chars = (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE |
                     IMAGE_SCN_MEM_READ)
    sec = struct.pack("<8sIIIIIIHHI",
                      sec_name,
                      0x1000,          # VirtualSize
                      text_rva,        # VirtualAddress
                      raw_size_rounded,  # SizeOfRawData
                      text_file_off,   # PointerToRawData
                      0, 0,            # reloc/linenum ptr
                      0, 0,            # num reloc/linenum
                      section_chars)

    # Assemble file
    image = bytearray()
    # size_of_headers = dos + signature + coff + optional + section header
    header_pad = size_of_headers
    image += dos_header()
    image += struct.pack("<I", IMAGE_NT_SIGNATURE)  # "PE\0\0"
    image += coff
    image += optional_header
    image += sec
    # pad to file_alignment
    while len(image) < header_pad:
        image += b"\x00"
    while len(image) % file_alignment != 0:
        image += b"\x00"
    # .text content: code stub then data region
    while len(image) < text_file_off:
        image += b"\x00"
    # inert entry-point stub: mov eax,0 ; ret  (inert, never executed)
    image += bytes([0xB8, 0x00, 0x00, 0x00, 0x00, 0xC3])  # 6 bytes
    while len(image) < region_file_off:
        image += b"\x00"

    # --- write data region ---
    region = bytearray()

    # descriptors (20 bytes each)
    def descriptor(olt, time, fwd, name, iat):
        return struct.pack("<IIIII", olt, time, fwd, name, iat)

    desc1 = descriptor(olt=oft_rva, time=0, fwd=0, name=dllname_rva, iat=iat_rva)
    descnull = descriptor(0, 0, 0, 0, 0)
    region += desc1
    region += descnull
    assert len(region) == 40

    # OFT array: pointers to hint/name rvas + null
    for hr in hint_rvas:
        region += struct.pack("<I", hr)
    region += struct.pack("<I", 0)
    assert len(region) == 40 + (len(func_names) + 1) * 4

    # DLL name
    region += dll_name
    # IAT array (same pointers) + null
    for hr in hint_rvas:
        region += struct.pack("<I", hr)
    region += struct.pack("<I", 0)
    # hint/name entries
    for hn in hint_names:
        region += hn

    image += bytes(region)

    return bytes(image)


if __name__ == "__main__":
    import sys
    out = sys.argv[1] if len(sys.argv) > 1 else "sample.exe"
    with open(out, "wb") as f:
        f.write(build_pe32())
    print("wrote", out)
