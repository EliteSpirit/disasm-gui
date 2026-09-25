"""
Ядро дизассемблера: разбор контейнера (PE / ELF / сырой дамп) и дизассемблирование
через Capstone. Здесь нет ни строчки tkinter, поэтому модуль можно тестировать
и использовать из консоли отдельно от GUI.
"""

from __future__ import annotations

import bisect
import re
import struct
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

# сколько нулей всего можно дописать к секциям PE (хвосты .bss и т.п.): VirtualSize в битом
# или вредоносном файле может быть любым, а выделять под него гигабайты памяти нельзя
MAX_PE_ZERO_FILL = 64 * 1024 * 1024

# типы символов ELF, которые показываем; STT_LOOS — это STT_GNU_IFUNC (memcpy, strlen в glibc)
_ELF_SYM_TYPES = ("STT_FUNC", "STT_OBJECT", "STT_LOOS")

# релокации x86-64, связывающие слот GOT с импортом
_R_X86_64_GLOB_DAT = 6
_R_X86_64_JUMP_SLOT = 7
_R_X86_64_IRELATIVE = 37


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

    def resolve(self, text: str) -> int | None:
        """
        Адрес по тому, что ввели в «Перейти»: сначала точное имя символа (иначе `f32addf64`
        из libm прочитался бы как hex), потом адрес, потом первый символ, где есть подстрока.
        """
        low = text.strip().lower()
        if not low:
            return None
        names = [(a, self.symbols[a].lower()) for a in self._sym_addrs]
        exact = next((a for a, n in names if n == low), None)
        if exact is not None:
            return exact
        try:
            return parse_address(low)
        except ValueError:
            pass
        return next((a for a, n in names if low in n), None)

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
    zero_budget = MAX_PE_ZERO_FILL
    for s in pe.sections:
        name = s.Name.rstrip(b"\x00").decode("latin-1") or "?"
        # в памяти секция может быть больше, чем на диске (.bss) — добиваем нулями,
        # но не больше общего лимита: VirtualSize = 0xF0000000 в файле на 90 КБ — не повод для MemoryError
        body = s.get_data()
        pad = min(max(0, s.Misc_VirtualSize - len(body)), zero_budget)
        zero_budget -= pad
        body += bytes(pad)
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
    # у ARM (Thumb-2) младший бит адреса кода — признак Thumb, а не часть адреса:
    # точка входа 0x4024cd на самом деле 0x4024cc, иначе листинг начинается с мусора
    thumb = arch_name == "ARM Thumb"

    def code_addr(addr: int) -> int:
        if thumb and any(sec.executable and sec.contains(addr) for sec in sections):
            return addr & ~1
        return addr

    exp = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
    if exp is not None:
        for s in exp.symbols:
            if s.name:
                symbols[code_addr(base + s.address)] = s.name.decode("latin-1", "replace")

    entry = code_addr(base + pe.OPTIONAL_HEADER.AddressOfEntryPoint)
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
        thumb_funcs = arm_funcs = 0
        for s in elf.iter_sections():
            if not isinstance(s, SymbolTableSection):
                continue
            for sym in s.iter_symbols():
                kind = sym["st_info"]["type"]
                value = sym["st_value"]
                # SHN_UNDEF — импорт; у не-PIE его «адрес» указывает на заглушку в .plt,
                # которую ниже подпишем как `name@plt`
                if not sym.name or not value or sym["st_shndx"] == "SHN_UNDEF" or kind not in _ELF_SYM_TYPES:
                    continue
                if arch_name == "ARM" and kind != "STT_OBJECT":
                    # у функций ARM младший бит адреса = Thumb-код
                    thumb_funcs += value & 1
                    arm_funcs += not value & 1
                    value &= ~1
                symbols.setdefault(value, sym.name)
        _add_plt_symbols(elf, symbols)

        entry = elf["e_entry"] or None
        if arch_name == "ARM":
            # Режим один на весь файл: Thumb, если с него стартует программа (нечётный e_entry),
            # а у библиотек без точки входа — если Thumb-функций больше. Смешанный ARM/Thumb-код
            # так не покрыть, но armhf-сборки почти целиком Thumb-2
            thumb = bool(entry & 1) if entry is not None else thumb_funcs > arm_funcs
            if thumb:
                arch_name = "ARM Thumb"
                arch, mode = RAW_ARCHS[arch_name]
            if entry is not None:
                entry &= ~1
        if entry is not None:
            symbols.setdefault(entry, "_start")
        return Binary(path, "ELF", arch_name, arch, mode, entry, sections, symbols)
    except ELFError as e:
        raise LoadError(f"Битый ELF: {e}") from e
    finally:
        f.close()


def _add_plt_symbols(elf, symbols: dict[int, str]) -> None:
    """
    Подписываем слоты GOT (`printf@got`) и заглушки .plt / .plt.sec / .plt.got (`printf@plt`)
    именами импортов. Только x86-64, самый частый случай.
    """
    from elftools.elf.sections import SymbolTableSection

    if elf["e_machine"] != "EM_X86_64":
        return
    got_to_name: dict[int, str] = {}
    fmt = "<QQq" if elf.little_endian else ">QQq"
    # .rela.plt — ленивые JUMP_SLOT, .rela.dyn — GLOB_DAT, на которые смотрит .plt.got
    for rela_name in (".rela.plt", ".rela.dyn"):
        rela = elf.get_section_by_name(rela_name)
        if rela is None or rela["sh_type"] != "SHT_RELA" or rela["sh_entsize"] != 24:
            continue
        dynsym = elf.get_section(rela["sh_link"])
        if not isinstance(dynsym, SymbolTableSection):
            continue
        data = rela.data()
        # struct вместо iter_relocations: в .rela.dyn больших бинарников сотни тысяч записей
        for offset, info, addend in struct.iter_unpack(fmt, data[:len(data) // 24 * 24]):
            kind, sym_idx = info & 0xFFFFFFFF, info >> 32
            if kind in (_R_X86_64_JUMP_SLOT, _R_X86_64_GLOB_DAT) and sym_idx:
                name = dynsym.get_symbol(sym_idx).name
            elif kind == _R_X86_64_IRELATIVE:
                # у IRELATIVE нет символа, но addend — адрес IFUNC-резолвера, а он обычно подписан
                name = symbols.get(addend)
            else:
                continue
            if name:
                got_to_name[offset] = name
    for slot, name in got_to_name.items():
        symbols.setdefault(slot, f"{name}@got")

    for sec_name in (".plt", ".plt.sec", ".plt.got"):
        sec = elf.get_section_by_name(sec_name)
        if sec is None or not sec["sh_addr"]:
            continue
        md = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
        md.detail = True
        prev = None
        for ins in md.disasm(sec.data(), sec["sh_addr"]):
            # с IBT заглушка начинается с endbr64 перед jmp; записи .plt.got без IBT
            # по 8 байт, так что выравнивать адрес на 16 нельзя
            stub = prev.address if prev is not None and prev.mnemonic == "endbr64" else ins.address
            prev = ins
            # jmp qword ptr [rip + X] — считаем, куда ссылается X
            if ins.mnemonic not in ("jmp", "bnd jmp") or "rip" not in ins.op_str:
                continue
            for op in ins.operands:
                if op.type == cs.x86.X86_OP_MEM and op.mem.base == cs.x86.X86_REG_RIP:
                    name = got_to_name.get(ins.address + ins.size + op.mem.disp)
                    if name:
                        symbols.setdefault(stub, f"{name}@plt")
