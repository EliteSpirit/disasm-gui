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
