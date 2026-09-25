from pathlib import Path

import pytest

import disasm_core as core

# push rbp; mov rbp, rsp; call +0; jmp -2; ret
CODE = bytes.fromhex("55 4889e5 e800000000 ebfe c3")


def raw(code=CODE, base=0x1000):
    return core.load_raw(Path("x.bin"), code, "x86-64", base)


def test_linear_disasm_and_groups():
    ins = raw().disassemble(0x1000, 10)
    assert [i.mnemonic for i in ins] == ["push", "mov", "call", "jmp", "ret"]
    assert [i.group for i in ins][2:] == ["call", "jump", "ret"]
    assert ins[2].target == 0x1009 and ins[3].target == 0x1009


def test_disassemble_before_ends_exactly_at_address():
    b = raw()
    before = b.disassemble_before(0x1009, 2)
    assert [i.address for i in before] == [0x1001, 0x1004]


def test_symbol_comment_on_call():
    b = raw()
    b.symbols[0x1009] = "loop"
    b.__post_init__()
    call = b.disassemble(0x1004, 1)[0]
    assert call.comment == "loop"
    assert b.symbol_for(0x100a) == "loop+0x1"


def test_skipdata_does_not_stop_listing():
    ins = raw(bytes.fromhex("06 90 c3")).disassemble(0x1000, 10)  # 06 невалиден в x86-64
    assert [i.mnemonic for i in ins][-2:] == ["nop", "ret"]


def test_search():
    b = raw()
    assert b.search_bytes(core.parse_hex_bytes("\\xeb\\xfe")) == [0x1009]
    assert [i.address for i in b.search_text("rbp, rsp")] == [0x1001]


@pytest.mark.parametrize("text,value", [("0x401000", 0x401000), ("401000h", 0x401000), ("ff", 0xFF)])
def test_parse_address(text, value):
    assert core.parse_address(text) == value


def test_bad_address_raises():
    with pytest.raises(core.LoadError):
        raw().disassemble(0x9999, 1)


@pytest.mark.skipif(not Path("/bin/ls").exists(), reason="нет /bin/ls")
def test_real_elf():
    b = core.load("/bin/ls")
    assert b.fmt == "ELF" and b.section_at(b.default_address()).executable
    assert b.disassemble(b.default_address(), 5)


# ------------------------------------------------ минимальные PE и ELF прямо в тесте


def make_pe(path, machine, entry_rva, sections):
    """PE32 без импортов. sections: (имя, RVA, VirtualSize, сырые байты, Characteristics)."""
    import struct

    file_align, headers = 0x200, 0x400
    raw_parts, headers_out, offset = [], [], headers
    for name, rva, vsize, raw, chars in sections:
        size = -(-len(raw) // file_align) * file_align
        headers_out.append(struct.pack("<8sIIIIIIHHI", name, vsize, rva, size, offset if raw else 0,
                                       0, 0, 0, 0, chars))
        raw_parts.append(raw.ljust(size, b"\x00"))
        offset += size
    image = max(rva + max(vsize, len(raw)) for _, rva, vsize, raw, _ in sections)
    opt = struct.pack("<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII", 0x10B, 14, 0, 0, 0, 0, entry_rva, 0x1000, 0,
                      0x400000, 0x1000, file_align, 6, 0, 0, 0, 6, 0, 0, -(-image // 0x1000) * 0x1000,
                      headers, 0, 3, 0, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16) + bytes(16 * 8)
    head = struct.pack("<HHIIIHH", machine, len(sections), 0, 0, 0, len(opt), 0x102)
    dos = b"MZ".ljust(0x3C, b"\x00") + struct.pack("<I", 0x40)
    data = (dos + b"PE\x00\x00" + head + opt + b"".join(headers_out)).ljust(headers, b"\x00")
    path.write_bytes(data + b"".join(raw_parts))
    return path


def make_arm_elf(path, code, thumb):
    """ELF32 ARM без таблицы секций: один исполняемый PT_LOAD, код сразу за заголовками."""
    import struct

    base, code_off = 0x10000, 0x100
    entry = base + code_off + (1 if thumb else 0)
    ident = b"\x7fELF\x01\x01\x01".ljust(16, b"\x00")
    ehdr = ident + struct.pack("<HHIIIIIHHHHHH", 2, 40, 1, entry, 52, 0, 0x05000000, 52, 32, 1, 40, 0, 0)
    size = code_off + len(code)
    phdr = struct.pack("<IIIIIIII", 1, 0, base, base, size, size, 5, 0x1000)
    path.write_bytes((ehdr + phdr).ljust(code_off, b"\x00") + code)
    return path


TEXT, DATA = 0x60000020, 0xC0000040  # CODE|EXECUTE|READ и INITIALIZED_DATA|READ|WRITE


def test_pe_huge_virtual_size_is_capped(tmp_path, monkeypatch):
    # VirtualSize = 0xF0000000 у секции в файле на пару КБ раньше выделял почти 4 ГБ нулей
    monkeypatch.setattr(core, "MAX_PE_ZERO_FILL", 0x3000)
    pe = make_pe(tmp_path / "bss.exe", 0x14C, 0x1000, [
        (b".text", 0x1000, 1, b"\xc3", TEXT),
        (b".bss", 0x2000, 0xF0000000, b"", DATA),
        (b".bss2", 0x10000, 0x0F000000, b"", DATA),
    ])
    b = core.load(pe)
    assert [len(s.data) for s in b.sections] == [0x200, 0x3000, 0]  # лимит общий на весь файл
    assert b.disassemble(b.entry, 1)[0].mnemonic == "ret"


def test_pe_arm_thumb_entry_bit_is_dropped(tmp_path):
    code = bytes.fromhex("80b5 0120 80bd")  # push {r7, lr}; movs r0, #1; pop {r7, pc}
    b = core.load(make_pe(tmp_path / "arm.exe", 0x1C4, 0x1001, [(b".text", 0x1000, len(code), code, TEXT)]))
    assert b.arch_name == "ARM Thumb" and b.entry == 0x401000
    assert b.symbols[0x401000] == "entry"
    assert [i.mnemonic for i in b.disassemble(b.entry, 3)] == ["push", "movs", "pop"]


def test_elf_arm_thumb_detected_by_entry(tmp_path):
    b = core.load(make_arm_elf(tmp_path / "t.elf", bytes.fromhex("80b5 0120 80bd"), thumb=True))
    assert b.arch_name == "ARM Thumb" and b.entry == 0x10100
    assert [i.mnemonic for i in b.disassemble(b.entry, 3)] == ["push", "movs", "pop"]


def test_elf_arm_mode_stays_arm(tmp_path):
    code = bytes.fromhex("00482de9 0100a0e3 0088bde8")  # push {fp, lr}; mov r0, #1; pop {fp, pc}
    b = core.load(make_arm_elf(tmp_path / "a.elf", code, thumb=False))
    assert b.arch_name == "ARM" and b.entry == 0x10100
    assert [i.mnemonic for i in b.disassemble(b.entry, 3)] == ["push", "mov", "pop"]


def test_resolve_prefers_exact_symbol_over_hex():
    b = raw()
    b.symbols.update({0x1004: "f32addf64", 0x1009: "loop_body"})
    b.__post_init__()
    assert b.resolve("f32addf64") == 0x1004  # без приоритета символа это был бы адрес 0xf32addf64
    assert b.resolve("0x1001") == 0x1001
    assert b.resolve("LOOP") == 0x1009  # подстрока без учёта регистра
    assert b.resolve("nope") is None


def _x86_64_elf(path):
    p = Path(path)
    head = p.read_bytes()[:20] if p.exists() else b""
    return head[:5] == b"\x7fELF\x02" and head[18:20] == b"\x3e\x00"  # ELF64, EM_X86_64


@pytest.mark.skipif(not _x86_64_elf("/bin/ls"), reason="нужен x86-64 ELF /bin/ls")
def test_real_elf_plt_and_got_names():
    import capstone as cs

    b = core.load("/bin/ls")
    # каждая заглушка jmp [rip + X] в .plt / .plt.sec / .plt.got подписана, включая 8-байтные .plt.got
    from elftools.elf.elffile import ELFFile

    with open("/bin/ls", "rb") as f:
        elf = ELFFile(f)
        stubs = [(s["sh_addr"], s.data()) for s in elf.iter_sections() if s.name in (".plt.sec", ".plt.got")]
    md = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
    for addr, data in stubs:
        for start, _size, mnem, ops in md.disasm_lite(data, addr):
            if "jmp" in mnem and "rip" in ops:
                stub = start - 4 if data[start - addr - 4:start - addr] == b"\xf3\x0f\x1e\xfa" else start
                assert b.symbols.get(stub, "").endswith("@plt"), hex(stub)
    # call [rip + X] на слот GOT подписан именем импорта, как IAT у PE
    comments = [i.comment for i in b.disassemble(b.entry, 20) if i.mnemonic == "call"]
    assert any("__libc_start_main@got" in c for c in comments)
