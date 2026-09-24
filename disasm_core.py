"""
Ядро дизассемблера: разбор контейнера (PE / ELF / сырой дамп) и дизассемблирование
через Capstone. Здесь нет ни строчки tkinter, поэтому модуль можно тестировать
и использовать из консоли отдельно от GUI.
"""

from __future__ import annotations

import bisect
import re
from dataclasses import dataclass, field
from pathlib import Path

import capstone as cs

# архитектуры, которые можно выбрать для сырого дампа: имя -> (arch, mode)
RAW_ARCHS: dict[str, tuple[int, int]] = {
    "x86-64": (cs.CS_ARCH_X86, cs.CS_MODE_64),
    "x86-32": (cs.CS_ARCH_X86, cs.CS_MODE_32),
    "x86-16": (cs.CS_ARCH_X86, cs.CS_MODE_16),
    "ARM64": (cs.CS_ARCH_ARM64, cs.CS_MODE_ARM),
    "ARM": (cs.CS_ARCH_ARM, cs.CS_MODE_ARM),
    "ARM Thumb": (cs.CS_ARCH_ARM, cs.CS_MODE_THUMB),
    "MIPS32 LE": (cs.CS_ARCH_MIPS, cs.CS_MODE_MIPS32 | cs.CS_MODE_LITTLE_ENDIAN),
    "MIPS32 BE": (cs.CS_ARCH_MIPS, cs.CS_MODE_MIPS32 | cs.CS_MODE_BIG_ENDIAN),
    "RISC-V 64": (cs.CS_ARCH_RISCV, cs.CS_MODE_RISCV64 | cs.CS_MODE_RISCVC),
}

# группы инструкций для подсветки
GROUP_CALL = "call"
GROUP_JUMP = "jump"
GROUP_RET = "ret"
GROUP_OTHER = "other"

_HEX_TARGET = re.compile(r"^#?(0x[0-9a-fA-F]+)$")


class LoadError(Exception):
    """Файл не удалось разобрать — текст сообщения показывается пользователю как есть."""


@dataclass
class Section:
    name: str
    vaddr: int
    offset: int
    data: bytes
    executable: bool

    @property
    def end(self) -> int:
        return self.vaddr + len(self.data)

    def contains(self, addr: int) -> bool:
        return self.vaddr <= addr < self.end


@dataclass
class Insn:
    address: int
    raw: bytes
    mnemonic: str
    op_str: str
    group: str = GROUP_OTHER
    target: int | None = None  # куда ведёт call/jmp, если адрес известен статически
    comment: str = ""


@dataclass
class Binary:
    path: Path
    fmt: str  # "PE", "ELF" или "RAW"
    arch_name: str
    arch: int
    mode: int
    entry: int | None
    sections: list[Section]
    symbols: dict[int, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self._sym_addrs = sorted(self.symbols)

    # --- адреса и символы ---

    def section_at(self, addr: int) -> Section | None:
        for sec in self.sections:
            if sec.contains(addr):
                return sec
        return None

    def symbol_for(self, addr: int) -> str | None:
        """Имя символа вида `func` или `func+0x1c`; None, если рядом ничего нет."""
        if addr in self.symbols:
            return self.symbols[addr]
        i = bisect.bisect_right(self._sym_addrs, addr) - 1
        if i < 0:
            return None
        base = self._sym_addrs[i]
        # не приклеиваем символ к адресу в другой секции — это почти всегда ложь
        sec = self.section_at(base)
        if sec is None or not sec.contains(addr) or addr - base > 0x10000:
            return None
        return f"{self.symbols[base]}+{addr - base:#x}"

    def default_address(self) -> int:
        if self.entry is not None and self.section_at(self.entry):
            return self.entry
        for sec in self.sections:
            if sec.executable:
                return sec.vaddr
        return self.sections[0].vaddr

    # --- дизассемблирование ---

    def _engine(self) -> cs.Cs:
        md = cs.Cs(self.arch, self.mode)
        md.detail = True
        # мусорные байты не должны обрывать листинг — capstone выведет их как .byte
        md.skipdata = True
        return md

    def disassemble(self, start: int, count: int) -> list[Insn]:
        """Не более `count` инструкций начиная с `start` (в пределах его секции)."""
        sec = self.section_at(start)
        if sec is None:
            raise LoadError(f"Адрес {start:#x} не попадает ни в одну секцию")
        md = self._engine()
        code = sec.data[start - sec.vaddr:]
        out: list[Insn] = []
        for ins in md.disasm(code, start, count):
            out.append(self._wrap(ins))
        return out

    def disassemble_before(self, addr: int, count: int) -> list[Insn]:
        """
        Инструкции, стоящие перед `addr`. У x86 переменная длина команд, поэтому
        честно «назад» дизассемблировать нельзя: берём с запасом кусок до адреса
        и оставляем хвост, который ровно упирается в `addr`.
        """
        sec = self.section_at(addr)
        if sec is None or addr == sec.vaddr:
            return []
        md = self._engine()
        for back in (count * 8, count * 16, count * 32):
            start = max(sec.vaddr, addr - back)
            code = sec.data[start - sec.vaddr:addr - sec.vaddr]
            insns = [self._wrap(i) for i in md.disasm(code, start)]
            if insns and insns[-1].address + len(insns[-1].raw) == addr:
                return insns[-count:]
            if start == sec.vaddr:
                break
        return []

    def _wrap(self, ins) -> Insn:
        group = GROUP_OTHER
        groups = set(ins.groups) if ins.id else set()
        if cs.CS_GRP_CALL in groups:
            group = GROUP_CALL
        elif cs.CS_GRP_RET in groups or cs.CS_GRP_IRET in groups:
            group = GROUP_RET
        elif cs.CS_GRP_JUMP in groups or cs.CS_GRP_BRANCH_RELATIVE in groups:
            group = GROUP_JUMP

        target = None
        comment = ""
        if group in (GROUP_CALL, GROUP_JUMP):
            m = _HEX_TARGET.match(ins.op_str.strip())
            if m:
                target = int(m.group(1), 16)
                # только точное имя: «_start+0x4840» в стрипнутом бинаре только путает
                name = self.symbols.get(target)
                if name:
                    comment = name
        if not comment and self.arch == cs.CS_ARCH_X86 and ins.id and "[" in ins.op_str:
            # [rip + X] и 32-битное [0x40a0c4] — показываем итоговый адрес: так видно,
            # куда смотрит lea / call [..] (в том числе имя импорта из IAT)
            for op in ins.operands:
                if op.type != cs.x86.X86_OP_MEM:
                    continue
                if op.mem.base == cs.x86.X86_REG_RIP:
                    ref = ins.address + ins.size + op.mem.disp
                elif op.mem.base == 0 and op.mem.index == 0 and op.mem.segment == 0:
                    ref = op.mem.disp & 0xFFFFFFFF
                    if ref not in self.symbols and self.section_at(ref) is None:
                        continue  # просто константа вроде [0x10], а не адрес в файле
                else:
                    continue
                name = self.symbols.get(ref)
                comment = f"{ref:#x}" + (f" {name}" if name else "")
                break
        return Insn(ins.address, bytes(ins.bytes), ins.mnemonic, ins.op_str, group, target, comment)

    # --- поиск ---

    def search_bytes(self, pattern: bytes, limit: int = 500) -> list[int]:
        hits: list[int] = []
        for sec in self.sections:
            pos = sec.data.find(pattern)
            while pos != -1 and len(hits) < limit:
                hits.append(sec.vaddr + pos)
                pos = sec.data.find(pattern, pos + 1)
        return hits

    def search_text(self, needle: str, limit: int = 500) -> list[Insn]:
        """Поиск по тексту инструкции (`mnemonic op_str`) во всех исполняемых секциях."""
        needle = needle.lower()
        hits: list[Insn] = []
        md = self._engine()
        md.detail = False
        for sec in self.sections:
            if not sec.executable:
                continue
            for addr, size, mnem, ops in md.disasm_lite(sec.data, sec.vaddr):
                if needle in f"{mnem} {ops}".lower():
                    raw = sec.data[addr - sec.vaddr:addr - sec.vaddr + size]
                    hits.append(Insn(addr, raw, mnem, ops))
                    if len(hits) >= limit:
                        return hits
        return hits


def parse_hex_bytes(text: str) -> bytes:
    """`48 8b 05` / `488b05` / `\\x48\\x8b` -> bytes. Бросает ValueError на мусоре."""
    cleaned = re.sub(r"(\\x|0x|[\s,])", "", text, flags=re.IGNORECASE)
    if not cleaned or len(cleaned) % 2:
        raise ValueError("нужно чётное количество hex-символов")
    return bytes.fromhex(cleaned)


def parse_address(text: str) -> int:
    text = text.strip().lower().replace("`", "").replace("_", "")
    if text.endswith("h"):
        text = "0x" + text[:-1]
    return int(text, 16) if not text.startswith("0x") else int(text, 0)


# ---------------------------------------------------------------- загрузчики


def load(path: str | Path, raw_arch: str = "x86-64", raw_base: int = 0) -> Binary:
    path = Path(path)
    try:
        data = path.read_bytes()
    except OSError as e:
        raise LoadError(f"Не удалось прочитать файл: {e}") from e
    if not data:
        raise LoadError("Файл пустой")
    if data[:2] == b"MZ":
        return _load_pe(path, data)
    if data[:4] == b"\x7fELF":
        return _load_elf(path)
    return load_raw(path, data, raw_arch, raw_base)


def load_raw(path: Path, data: bytes, arch_name: str, base: int) -> Binary:
    if arch_name not in RAW_ARCHS:
        raise LoadError(f"Неизвестная архитектура: {arch_name}")
    arch, mode = RAW_ARCHS[arch_name]
    sec = Section("raw", base, 0, data, True)
    return Binary(path, "RAW", arch_name, arch, mode, base, [sec])


def _load_pe(path: Path, data: bytes) -> Binary:
    import pefile

    try:
        pe = pefile.PE(data=data, fast_load=True)
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
        ])
    except pefile.PEFormatError as e:
        raise LoadError(f"Битый PE: {e}") from e

    machines = {
        0x14C: "x86-32",
        0x8664: "x86-64",
        0xAA64: "ARM64",
        0x1C0: "ARM",
        0x1C4: "ARM Thumb",
    }
    arch_name = machines.get(pe.FILE_HEADER.Machine)
    if arch_name is None:
        raise LoadError(f"Неподдерживаемая архитектура PE: {pe.FILE_HEADER.Machine:#x}")
    arch, mode = RAW_ARCHS[arch_name]

    base = pe.OPTIONAL_HEADER.ImageBase
    sections = []
    for s in pe.sections:
        name = s.Name.rstrip(b"\x00").decode("latin-1") or "?"
        # в памяти секция может быть больше, чем на диске (.bss) — добиваем нулями
        body = s.get_data()
        size = max(s.Misc_VirtualSize, len(body)) if s.Misc_VirtualSize else len(body)
        body = body[:size].ljust(size, b"\x00")
        exe = bool(s.Characteristics & 0x20000000)  # IMAGE_SCN_MEM_EXECUTE
        sections.append(Section(name, base + s.VirtualAddress, s.PointerToRawData, body, exe))
    if not sections:
        raise LoadError("В PE нет секций")

    symbols: dict[int, str] = {}
    for imp in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        dll = imp.dll.decode("latin-1", "replace").rsplit(".", 1)[0]
        for f in imp.imports:
            fname = f.name.decode("latin-1", "replace") if f.name else f"#{f.ordinal}"
            symbols[f.address] = f"{dll}!{fname}"
    exp = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
    if exp is not None:
        for s in exp.symbols:
            if s.name:
                symbols[base + s.address] = s.name.decode("latin-1", "replace")

    entry = base + pe.OPTIONAL_HEADER.AddressOfEntryPoint
    symbols.setdefault(entry, "entry")
    pe.close()
    return Binary(path, "PE", arch_name, arch, mode, entry, sections, symbols)


def _load_elf(path: Path) -> Binary:
    from elftools.common.exceptions import ELFError
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection

    try:
        f = open(path, "rb")  # noqa: SIM115 — ELFFile читает лениво, закрываем в finally
    except OSError as e:
        raise LoadError(f"Не удалось открыть файл: {e}") from e
    try:
        elf = ELFFile(f)
        machine = elf["e_machine"]
        is64 = elf.elfclass == 64
        little = elf.little_endian
        if machine == "EM_X86_64":
            arch_name = "x86-64"
        elif machine == "EM_386":
            arch_name = "x86-32"
        elif machine == "EM_AARCH64":
            arch_name = "ARM64"
        elif machine == "EM_ARM":
            arch_name = "ARM"
        elif machine == "EM_MIPS" and not is64:
            arch_name = "MIPS32 LE" if little else "MIPS32 BE"
        elif machine == "EM_RISCV" and is64:
            arch_name = "RISC-V 64"
        else:
            raise LoadError(f"Неподдерживаемая архитектура ELF: {machine}")
        arch, mode = RAW_ARCHS[arch_name]

        sections = []
        for s in elf.iter_sections():
            if not s["sh_addr"] or s["sh_type"] == "SHT_NOBITS":
                continue
            exe = bool(s["sh_flags"] & 0x4)  # SHF_EXECINSTR
            sections.append(Section(s.name or "?", s["sh_addr"], s["sh_offset"], s.data(), exe))
        if not sections:
            # stripped-бинарник без таблицы секций — берём исполняемые сегменты
            for i, seg in enumerate(elf.iter_segments()):
                if seg["p_type"] == "PT_LOAD":
                    exe = bool(seg["p_flags"] & 0x1)
                    sections.append(Section(f"LOAD{i}", seg["p_vaddr"], seg["p_offset"], seg.data(), exe))
        if not sections:
            raise LoadError("В ELF нет загружаемых секций")

        symbols: dict[int, str] = {}
        for s in elf.iter_sections():
            if not isinstance(s, SymbolTableSection):
                continue
            for sym in s.iter_symbols():
                if sym.name and sym["st_value"] and sym["st_info"]["type"] in ("STT_FUNC", "STT_OBJECT"):
                    symbols.setdefault(sym["st_value"] & ~1 if arch_name == "ARM" else sym["st_value"],
                                       sym.name)
        _add_plt_symbols(elf, sections, symbols)

        entry = elf["e_entry"] or None
        if entry is not None:
            symbols.setdefault(entry, "_start")
        return Binary(path, "ELF", arch_name, arch, mode, entry, sections, symbols)
    except ELFError as e:
        raise LoadError(f"Битый ELF: {e}") from e
    finally:
        f.close()


def _add_plt_symbols(elf, sections: list[Section], symbols: dict[int, str]) -> None:
    """Подписываем заглушки .plt / .plt.sec именами импортов (только x86-64, самый частый случай)."""
    if elf["e_machine"] != "EM_X86_64":
        return
    rela = elf.get_section_by_name(".rela.plt")
    if rela is None:
        return
    dynsym = elf.get_section(rela["sh_link"])
    got_to_name = {}
    for r in rela.iter_relocations():
        name = dynsym.get_symbol(r["r_info_sym"]).name
        if name:
            got_to_name[r["r_offset"]] = name
    for sec in sections:
        if sec.name not in (".plt", ".plt.sec", ".plt.got"):
            continue
        md = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
        md.detail = True
        for ins in md.disasm(sec.data, sec.vaddr):
            # jmp qword ptr [rip + X] — считаем, куда ссылается X
            if ins.mnemonic in ("jmp", "bnd jmp") and "rip" in ins.op_str:
                for op in ins.operands:
                    if op.type == cs.x86.X86_OP_MEM and op.mem.base == cs.x86.X86_REG_RIP:
                        slot = ins.address + ins.size + op.mem.disp
                        if slot in got_to_name:
                            stub = ins.address & ~0xF
                            symbols.setdefault(stub, f"{got_to_name[slot]}@plt")
