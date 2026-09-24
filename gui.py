"""
Disasm GUI — тёмный графический дизассемблер на CustomTkinter + Capstone.

Открывает PE (.exe/.dll), ELF и сырые дампы (архитектуру спросит при открытии).
Листинг бесконечно подгружается при прокрутке, call/jmp кликабельны, есть
история переходов, поиск по тексту инструкций и по байтам.

Чтобы окно не подвисало, всё тяжёлое (загрузка файла, поиск по всему бинарнику)
идёт в фоновом потоке, а в листинге одновременно держится не больше
MAX_ROWS строк — остальное догружается кусками по мере прокрутки.

Запуск:
  pip install -r requirements.txt
  python gui.py [файл]

Горячие клавиши:
  Ctrl+O — открыть        Ctrl+G — перейти к адресу    Ctrl+F — поиск
  Enter  — перейти по call/jmp в текущей строке
  Esc / Alt+← — назад     Alt+→ — вперёд
  ↑ ↓ PgUp PgDn — по строкам       Ctrl+C — скопировать строку
  Ctrl+колесо / Ctrl+= / Ctrl+- — размер шрифта
"""

from __future__ import annotations

import queue
import sys
import threading
import tkinter as tk
import tkinter.font as tkfont
from pathlib import Path
from tkinter import filedialog

import customtkinter as ctk

import disasm_core as core

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

# --- палитра (та же, что в zapret-gui, плюс цвета подсветки кода) ---
COLOR_BG = "#0b0d12"
COLOR_CARD = "#141821"
COLOR_CARD_BORDER = "#242a36"
COLOR_ACCENT = "#2ee673"
COLOR_ACCENT_HOVER = "#4dffa0"
COLOR_ACCENT_DIM = "#1e5a34"
COLOR_TEXT = "#e6e8eb"
COLOR_MUTED = "#7d8590"
COLOR_DIM = "#4a525e"
COLOR_CODE_BG = "#080a0d"
COLOR_ROW_HOVER = "#12161d"
COLOR_ROW_CURRENT = "#1a2230"
COLOR_OPS = "#c9d1d9"
COLOR_CALL = "#58a6ff"
COLOR_JUMP = "#e3b341"
COLOR_RET = "#ff7b72"
COLOR_COMMENT = "#6a9955"
COLOR_ERROR = "#ff7b72"

CORNER_RADIUS = 10
FRAME_MS = 15

CHUNK = 600  # сколько инструкций догружать за раз при прокрутке
MAX_ROWS = 4000  # больше строк в tk.Text не держим — иначе вставка/удаление начинают тормозить
EDGE = 0.04  # насколько близко к краю листинга нужно докрутить, чтобы начать догрузку
MAX_BYTES_SHOWN = 8

MONO_CANDIDATES = ("Cascadia Mono", "Consolas", "JetBrains Mono", "Fira Code", "DejaVu Sans Mono",
                   "Menlo", "Courier New")


def _lerp_color(c1: str, c2: str, t: float) -> str:
    c1, c2 = c1.lstrip("#"), c2.lstrip("#")
    a = [int(c1[i:i + 2], 16) for i in (0, 2, 4)]
    b = [int(c2[i:i + 2], 16) for i in (0, 2, 4)]
    return "#" + "".join(f"{round(x + (y - x) * t):02x}" for x, y in zip(a, b))


def _ease_out(t: float) -> float:
    return 1 - (1 - t) ** 3


class Row:
    """Строка листинга: либо метка символа (`label`), либо сама инструкция."""

    __slots__ = ("insn", "label")

    def __init__(self, insn: core.Insn, label: str | None = None):
        self.insn = insn
        self.label = label


class RawDialog(ctk.CTkToplevel):
    """Спрашивает архитектуру и базовый адрес для файла без заголовка."""

    def __init__(self, master, filename: str):
        super().__init__(master)
        self.result: tuple[str, int] | None = None
        self.title("Сырой дамп")
        self.configure(fg_color=COLOR_BG)
        self.resizable(False, False)
        self.transient(master)

        ctk.CTkLabel(self, text=f"«{filename}» — не PE и не ELF.",
                     text_color=COLOR_TEXT, font=ctk.CTkFont(size=14, weight="bold")).pack(
            padx=20, pady=(18, 2), anchor="w")
        ctk.CTkLabel(self, text="Как его дизассемблировать?", text_color=COLOR_MUTED).pack(
            padx=20, anchor="w")

        form = ctk.CTkFrame(self, fg_color=COLOR_CARD, corner_radius=CORNER_RADIUS,
                            border_width=1, border_color=COLOR_CARD_BORDER)
        form.pack(padx=20, pady=14, fill="x")
        ctk.CTkLabel(form, text="Архитектура", text_color=COLOR_MUTED).grid(
            row=0, column=0, padx=(14, 10), pady=(12, 6), sticky="w")
        self.arch = ctk.CTkOptionMenu(form, values=list(core.RAW_ARCHS), width=180,
                                      fg_color=COLOR_CARD_BORDER, button_color=COLOR_CARD_BORDER,
                                      button_hover_color=COLOR_ACCENT_DIM)
        self.arch.grid(row=0, column=1, padx=(0, 14), pady=(12, 6))
        ctk.CTkLabel(form, text="Базовый адрес", text_color=COLOR_MUTED).grid(
            row=1, column=0, padx=(14, 10), pady=(6, 12), sticky="w")
        self.base = ctk.CTkEntry(form, width=180, placeholder_text="0x0")
        self.base.grid(row=1, column=1, padx=(0, 14), pady=(6, 12))

        self.err = ctk.CTkLabel(self, text="", text_color=COLOR_ERROR)
        self.err.pack(padx=20, anchor="w")

        btns = ctk.CTkFrame(self, fg_color="transparent")
        btns.pack(padx=20, pady=(4, 18), fill="x")
        ctk.CTkButton(btns, text="Открыть", command=self._ok, fg_color=COLOR_ACCENT,
                      hover_color=COLOR_ACCENT_HOVER, text_color="#06120b", width=110).pack(side="right")
        ctk.CTkButton(btns, text="Отмена", command=self.destroy, fg_color="transparent",
                      border_width=1, border_color=COLOR_CARD_BORDER, hover_color=COLOR_CARD,
                      width=90).pack(side="right", padx=8)

        self.bind("<Return>", lambda e: self._ok())
        self.bind("<Escape>", lambda e: self.destroy())
        self.after(50, self._grab)

    def _grab(self):
        try:
            self.grab_set()
            self.base.focus_set()
        except tk.TclError:
            pass

    def _ok(self):
        text = self.base.get().strip() or "0"
        try:
            base = core.parse_address(text)
        except ValueError:
            self.err.configure(text="Адрес — это hex, например 0x400000")
            return
        self.result = (self.arch.get(), base)
        self.destroy()


class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Disasm GUI")
        self.geometry("1280x800")
        self.minsize(900, 520)
        self.configure(fg_color=COLOR_BG)

        self.binary: core.Binary | None = None
        self.rows: list[Row] = []
        self.cur_addr: int | None = None
        self.back: list[int] = []
        self.forward: list[int] = []
        self._extending = False
        self._busy = 0
        self._jobs: queue.Queue = queue.Queue()
        self._sym_items: list[tuple[int, str]] = []
        self._sym_shown: list[int] = []
        self._search_hits: list[int] = []
        self._filter_job = None
        self._flash_job = None
        self._hover_line = None

        families = set(tkfont.families(self))
        mono = next((f for f in MONO_CANDIDATES if f in families), "TkFixedFont")
        self.mono = tkfont.Font(self, family=mono, size=11)
        self.mono_bold = tkfont.Font(self, family=mono, size=11, weight="bold")

        self._build_toolbar()
        self._build_body()
        self._build_statusbar()
        self._bind_keys()
        self._show_welcome(True)
        self.after(30, self._poll_jobs)

    # ------------------------------------------------------------------ layout

    def _build_toolbar(self):
        bar = ctk.CTkFrame(self, fg_color=COLOR_CARD, corner_radius=0, height=52)
        bar.pack(fill="x")
        ctk.CTkFrame(self, fg_color=COLOR_CARD_BORDER, height=1, corner_radius=0).pack(fill="x")

        btn = dict(height=32, corner_radius=8, fg_color="transparent", border_width=1,
                   border_color=COLOR_CARD_BORDER, hover_color=COLOR_ROW_CURRENT, text_color=COLOR_TEXT)
        ctk.CTkButton(bar, text="Открыть", width=110, command=self.open_dialog, **btn).pack(
            side="left", padx=(12, 6), pady=10)
        self.btn_back = ctk.CTkButton(bar, text="◀", width=36, command=self.go_back, **btn)
        self.btn_back.pack(side="left", padx=(6, 2))
        self.btn_fwd = ctk.CTkButton(bar, text="▶", width=36, command=self.go_forward, **btn)
        self.btn_fwd.pack(side="left", padx=(2, 12))

        entry = dict(height=32, corner_radius=8, fg_color=COLOR_CODE_BG, border_color=COLOR_CARD_BORDER,
                     text_color=COLOR_TEXT, font=ctk.CTkFont(family=self.mono.actual("family"), size=13))
        self.goto_entry = ctk.CTkEntry(bar, width=190, placeholder_text="адрес или символ   Ctrl+G", **entry)
        self.goto_entry.pack(side="left")
        self.goto_entry.bind("<Return>", lambda e: self._goto_from_entry())

        self.search_mode = ctk.CTkSegmentedButton(
            bar, values=["Текст", "Байты"], height=32, corner_radius=8,
            selected_color=COLOR_ACCENT_DIM, selected_hover_color=COLOR_ACCENT_DIM,
            unselected_color=COLOR_CODE_BG, unselected_hover_color=COLOR_ROW_CURRENT)
        self.search_mode.set("Текст")
        self.search_mode.pack(side="right", padx=(6, 12))
        self.search_entry = ctk.CTkEntry(bar, width=260, placeholder_text="поиск: mov rax / 0f 05   Ctrl+F",
                                         **entry)
        self.search_entry.pack(side="right")
        self.search_entry.bind("<Return>", lambda e: self.run_search())

        # тонкая акцентная полоска-прогресс под тулбаром: видно, что идёт работа
        self.progress = ctk.CTkProgressBar(self, height=2, corner_radius=0, mode="indeterminate",
                                           progress_color=COLOR_ACCENT, fg_color=COLOR_BG)

    def _build_body(self):
        body = ctk.CTkFrame(self, fg_color=COLOR_BG, corner_radius=0)
        body.pack(fill="both", expand=True, padx=10, pady=10)
        self.body = body

        side = ctk.CTkTabview(body, width=300, fg_color=COLOR_CARD, corner_radius=CORNER_RADIUS,
                              border_width=1, border_color=COLOR_CARD_BORDER,
                              segmented_button_selected_color=COLOR_ACCENT_DIM,
                              segmented_button_selected_hover_color=COLOR_ACCENT_DIM,
                              segmented_button_unselected_color=COLOR_CARD,
                              segmented_button_fg_color=COLOR_CARD)
        side.pack(side="left", fill="y", padx=(0, 10))
        side.pack_propagate(False)
        self.side = side
        for name in ("Секции", "Символы", "Поиск"):
            side.add(name)

        self.sec_list = self._make_listbox(side.tab("Секции"))
        self.sec_list.bind("<<ListboxSelect>>", self._on_section_pick)

        self.sym_filter = ctk.CTkEntry(side.tab("Символы"), height=30, placeholder_text="фильтр…",
                                       fg_color=COLOR_CODE_BG, border_color=COLOR_CARD_BORDER)
        self.sym_filter.pack(fill="x", padx=2, pady=(0, 6))
        self.sym_filter.bind("<KeyRelease>", lambda e: self._schedule_filter())
        self.sym_list = self._make_listbox(side.tab("Символы"))
        self.sym_list.bind("<<ListboxSelect>>", self._on_symbol_pick)

        self.search_info = ctk.CTkLabel(side.tab("Поиск"), text="Пока ничего не искали",
                                        text_color=COLOR_MUTED, anchor="w")
        self.search_info.pack(fill="x", padx=4, pady=(0, 4))
        self.hit_list = self._make_listbox(side.tab("Поиск"))
        self.hit_list.bind("<<ListboxSelect>>", self._on_hit_pick)

        # --- листинг ---
        card = ctk.CTkFrame(body, fg_color=COLOR_CODE_BG, corner_radius=CORNER_RADIUS,
                            border_width=1, border_color=COLOR_CARD_BORDER)
        card.pack(side="left", fill="both", expand=True)
        self.card = card

        self.text = tk.Text(card, bg=COLOR_CODE_BG, fg=COLOR_TEXT, font=self.mono, wrap="none",
                            borderwidth=0, highlightthickness=0, padx=14, pady=10, cursor="arrow",
                            insertwidth=0, selectbackground=COLOR_ROW_CURRENT, spacing1=1, spacing3=1,
                            undo=False, state="disabled")
        sb = ctk.CTkScrollbar(card, command=self.text.yview, button_color=COLOR_CARD_BORDER,
                              button_hover_color=COLOR_DIM)
        sb.pack(side="right", fill="y", padx=(0, 4), pady=8)
        self.text.pack(side="left", fill="both", expand=True, padx=(4, 0), pady=4)
        self.scrollbar = sb
        self.text.configure(yscrollcommand=self._on_yscroll)

        t = self.text
        t.tag_configure("addr", foreground=COLOR_MUTED)
        t.tag_configure("bytes", foreground=COLOR_DIM)
        t.tag_configure("mnem", foreground=COLOR_TEXT)
        t.tag_configure("m_call", foreground=COLOR_CALL)
        t.tag_configure("m_jump", foreground=COLOR_JUMP)
        t.tag_configure("m_ret", foreground=COLOR_RET)
        t.tag_configure("ops", foreground=COLOR_OPS)
        t.tag_configure("link", foreground=COLOR_ACCENT)
        t.tag_configure("comment", foreground=COLOR_COMMENT)
        t.tag_configure("label", foreground=COLOR_ACCENT, font=self.mono_bold, spacing1=10)
        t.tag_configure("hover", background=COLOR_ROW_HOVER)
        t.tag_configure("current", background=COLOR_ROW_CURRENT)
        t.tag_configure("flash", background=COLOR_ACCENT_DIM)
        # приоритеты: вспышка поверх текущей строки, текущая поверх наведения
        t.tag_raise("current", "hover")
        t.tag_raise("flash", "current")

        t.tag_bind("link", "<Enter>", lambda e: t.configure(cursor="hand2"))
        t.tag_bind("link", "<Leave>", lambda e: t.configure(cursor="arrow"))
        t.tag_bind("link", "<Button-1>", self._on_link_click)
        t.bind("<Button-1>", self._on_text_click, add="+")
        t.bind("<Motion>", self._on_motion)
        t.bind("<Leave>", lambda e: self._set_hover(None))
        t.bind("<Control-MouseWheel>", self._on_zoom_wheel)
        t.bind("<Control-Button-4>", lambda e: self.zoom(+1))
        t.bind("<Control-Button-5>", lambda e: self.zoom(-1))

        # заглушка «открой файл», пока ничего не загружено
        self.welcome = ctk.CTkFrame(card, fg_color=COLOR_CODE_BG, corner_radius=CORNER_RADIUS)
        inner = ctk.CTkFrame(self.welcome, fg_color="transparent")
        inner.place(relx=0.5, rely=0.45, anchor="center")
        ctk.CTkLabel(inner, text="⟨/⟩", font=ctk.CTkFont(size=44, weight="bold"),
                     text_color=COLOR_ACCENT).pack()
        ctk.CTkLabel(inner, text="Открой бинарник", font=ctk.CTkFont(size=20, weight="bold"),
                     text_color=COLOR_TEXT).pack(pady=(6, 2))
        ctk.CTkLabel(inner, text="PE (.exe, .dll), ELF или сырой дамп — архитектуру спрошу",
                     text_color=COLOR_MUTED).pack()
        ctk.CTkButton(inner, text="Выбрать файл   Ctrl+O", command=self.open_dialog, height=38,
                      corner_radius=8, fg_color=COLOR_ACCENT, hover_color=COLOR_ACCENT_HOVER,
                      text_color="#06120b", font=ctk.CTkFont(weight="bold")).pack(pady=(18, 0))

    def _make_listbox(self, parent) -> tk.Listbox:
        # обычный tk.Listbox, а не CTk-виджеты построчно: тысячи символов в нём не тормозят
        frame = ctk.CTkFrame(parent, fg_color=COLOR_CODE_BG, corner_radius=8)
        frame.pack(fill="both", expand=True, padx=2, pady=(0, 2))
        lb = tk.Listbox(frame, bg=COLOR_CODE_BG, fg=COLOR_OPS, font=(self.mono.actual("family"), 10),
                        borderwidth=0, highlightthickness=0, activestyle="none",
                        selectbackground=COLOR_ACCENT_DIM, selectforeground=COLOR_TEXT,
                        exportselection=False)
        sb = ctk.CTkScrollbar(frame, command=lb.yview, button_color=COLOR_CARD_BORDER,
                              button_hover_color=COLOR_DIM, width=12)
        lb.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y", pady=4)
        lb.pack(side="left", fill="both", expand=True, padx=(8, 0), pady=6)
        return lb

    def _build_statusbar(self):
        bar = ctk.CTkFrame(self, fg_color=COLOR_CARD, corner_radius=0, height=28)
        bar.pack(fill="x", side="bottom", before=self.body)
        line = ctk.CTkFrame(self, fg_color=COLOR_CARD_BORDER, height=1, corner_radius=0)
        line.pack(fill="x", side="bottom", before=self.body)
        self.status_left = ctk.CTkLabel(bar, text="Файл не открыт", text_color=COLOR_MUTED, anchor="w")
        self.status_left.pack(side="left", padx=12)
        self.status_right = ctk.CTkLabel(bar, text="", text_color=COLOR_MUTED, anchor="e",
                                         font=ctk.CTkFont(family=self.mono.actual("family"), size=12))
        self.status_right.pack(side="right", padx=12)

    def _bind_keys(self):
        self.bind_all("<Control-o>", lambda e: self.open_dialog())
        self.bind_all("<Control-g>", lambda e: self._focus_entry(self.goto_entry))
        self.bind_all("<Control-f>", lambda e: self._focus_entry(self.search_entry))
        self.bind_all("<Alt-Left>", lambda e: self.go_back())
        self.bind_all("<Alt-Right>", lambda e: self.go_forward())
        self.bind_all("<Control-equal>", lambda e: self.zoom(+1))
        self.bind_all("<Control-plus>", lambda e: self.zoom(+1))
        self.bind_all("<Control-minus>", lambda e: self.zoom(-1))
        t = self.text
        t.bind("<Escape>", lambda e: self.go_back())
        t.bind("<Return>", lambda e: self.follow_current())
        t.bind("<Up>", lambda e: self.move_cursor(-1))
        t.bind("<Down>", lambda e: self.move_cursor(+1))
        t.bind("<Prior>", lambda e: self.move_cursor(-self._page()))
        t.bind("<Next>", lambda e: self.move_cursor(+self._page()))
        t.bind("<Control-c>", lambda e: self.copy_current())

    def _focus_entry(self, entry):
        entry.focus_set()
        entry.select_range(0, "end")
        return "break"

    # ------------------------------------------------------------ фоновые задачи

    def run_bg(self, work, done, label: str):
        """Выполняет `work()` в потоке, `done(result, error)` вызывается уже в GUI-потоке."""
        self._set_busy(+1, label)

        def runner():
            try:
                res, err = work(), None
            except Exception as e:  # noqa: BLE001 — любую ошибку показываем пользователю
                res, err = None, e
            self._jobs.put((done, res, err))

        threading.Thread(target=runner, daemon=True).start()

    def _poll_jobs(self):
        try:
            while True:
                done, res, err = self._jobs.get_nowait()
                self._set_busy(-1)
                done(res, err)
        except queue.Empty:
            pass
        self.after(30, self._poll_jobs)

    def _set_busy(self, delta: int, label: str = ""):
        self._busy += delta
        if self._busy > 0:
            if label:
                self.status_left.configure(text=label, text_color=COLOR_ACCENT)
            if not self.progress.winfo_ismapped():
                self.progress.pack(fill="x", before=self.body)
                self.progress.start()
        else:
            self.progress.stop()
            self.progress.pack_forget()
            self._update_status_left()

    # ------------------------------------------------------------------ загрузка

    def open_dialog(self):
        path = filedialog.askopenfilename(parent=self, title="Открыть бинарник")
        if path:
            self.open_path(path)
        return "break"

    def open_path(self, path: str):
        p = Path(path)
        raw_opts = None
        try:
            with open(p, "rb") as f:
                head = f.read(4)
        except OSError as e:
            self._error(f"Не удалось открыть: {e}")
            return
        if head[:2] != b"MZ" and head != b"\x7fELF":
            dlg = RawDialog(self, p.name)
            self.wait_window(dlg)
            if dlg.result is None:
                return
            raw_opts = dlg.result

        def work():
            if raw_opts:
                return core.load_raw(p, p.read_bytes(), *raw_opts)
            return core.load(p)

        self.run_bg(work, self._on_loaded, f"Загружаю {p.name}…")

    def _on_loaded(self, binary: core.Binary | None, err: Exception | None):
        if err is not None:
            self._error(str(err) if isinstance(err, core.LoadError) else f"Ошибка: {err!r}")
            return
        self.binary = binary
        self.back.clear()
        self.forward.clear()
        self.title(f"Disasm GUI — {binary.path.name}")
        self._fill_sections()
        self._sym_items = sorted(binary.symbols.items())
        self._apply_filter()
        self.hit_list.delete(0, "end")
        self.search_info.configure(text="Пока ничего не искали")
        self._show_welcome(False)
        self._update_status_left()
        self.goto(binary.default_address(), record=False)
        self.text.focus_set()

    def _fill_sections(self):
        self.sec_list.delete(0, "end")
        for i, s in enumerate(self.binary.sections):
            flag = "x" if s.executable else " "
            self.sec_list.insert("end", f"{flag} {s.name:<10.10} {s.vaddr:>#12x}  {len(s.data):>#8x}")
            self.sec_list.itemconfigure(i, foreground=COLOR_TEXT if s.executable else COLOR_MUTED)

    def _show_welcome(self, show: bool):
        if show:
            self.welcome.place(relx=0, rely=0, relwidth=1, relheight=1)
            self.welcome.lift()
        else:
            self.welcome.place_forget()

    # ---------------------------------------------------------------- навигация

    def goto(self, addr: int, record: bool = True):
        b = self.binary
        if b is None:
            return
        sec = b.section_at(addr)
        if sec is None:
            self._error(f"{addr:#x} вне секций файла")
            return
        if record and self.cur_addr is not None and self.cur_addr != addr:
            self.back.append(self.cur_addr)
            self.forward.clear()

        row = self._row_index(addr)
        if row is None:
            # адреса нет в текущем окне — перерисовываем окно вокруг него
            before = b.disassemble_before(addr, CHUNK // 3)
            after = b.disassemble(addr, CHUNK)
            self._render(before + after)
            row = self._row_index(addr)
        self.cur_addr = addr
        self._highlight_current()
        if row is not None:
            self._center_on(row)
            self._flash(row)
        self._update_nav_buttons()
        self._update_status_right()

    def go_back(self):
        if self.back:
            self.forward.append(self.cur_addr)
            self.goto(self.back.pop(), record=False)
        return "break"

    def go_forward(self):
        if self.forward:
            self.back.append(self.cur_addr)
            self.goto(self.forward.pop(), record=False)
        return "break"

    def _goto_from_entry(self):
        text = self.goto_entry.get().strip()
        if not text or self.binary is None:
            return
        addr = self._resolve(text)
        if addr is None:
            self._error(f"Не нашёл адрес или символ «{text}»")
            return
        self.goto(addr)
        self.text.focus_set()

    def _resolve(self, text: str) -> int | None:
        try:
            return core.parse_address(text)
        except ValueError:
            pass
        low = text.lower()
        exact = [a for a, n in self._sym_items if n.lower() == low]
        if exact:
            return exact[0]
        partial = [a for a, n in self._sym_items if low in n.lower()]
        return partial[0] if partial else None

    def follow_current(self):
        row = self._row_index(self.cur_addr) if self.cur_addr is not None else None
        if row is not None and self.rows[row].insn.target is not None:
            self.goto(self.rows[row].insn.target)
        return "break"

    def move_cursor(self, delta: int):
        if not self.rows or self.cur_addr is None:
            return "break"
        row = self._row_index(self.cur_addr) or 0
        row = max(0, min(len(self.rows) - 1, row + delta))
        # метки символов пропускаем — курсор ходит только по инструкциям
        while self.rows[row].label is not None and 0 < row < len(self.rows) - 1:
            row += 1 if delta > 0 else -1
        self.cur_addr = self.rows[row].insn.address
        self._highlight_current()
        self.text.see(f"{row + 1}.0")
        self._update_status_right()
        return "break"

    def _page(self) -> int:
        return max(1, self.text.winfo_height() // max(1, self.mono.metrics("linespace") + 2) - 2)

    # -------------------------------------------------------------- рендеринг

    def _make_rows(self, insns: list[core.Insn]) -> list[Row]:
        rows = []
        syms = self.binary.symbols
        for ins in insns:
            name = syms.get(ins.address)
            if name:
                rows.append(Row(ins, name))
            rows.append(Row(ins))
        return rows

    def _line_chunks(self, row: Row) -> tuple:
        ins = row.insn
        w = 16 if ins.address > 0xFFFFFFFF else 8
        if row.label is not None:
            return (f"{' ' * (w + 2)}{row.label}:\n", "label")
        if len(ins.raw) > MAX_BYTES_SHOWN:  # длинные команды обрезаем, чтобы колонки не поехали
            raw = ins.raw[:MAX_BYTES_SHOWN - 1].hex(" ") + " …"
        else:
            raw = ins.raw.hex(" ")
        mtag = {"call": "m_call", "jump": "m_jump", "ret": "m_ret"}.get(ins.group, "mnem")
        parts = [f"{ins.address:0{w}x}  ", "addr", f"{raw:<{MAX_BYTES_SHOWN * 3}} ", "bytes",
                 f"{ins.mnemonic:<8} ", mtag]
        if ins.target is not None and ins.group in ("call", "jump"):
            parts += [ins.op_str, "link"]
        else:
            parts += [ins.op_str, "ops"]
        if ins.comment:
            parts += [f"   ; {ins.comment}", "comment"]
        parts += ["\n", ()]
        return tuple(parts)

    def _insert_rows(self, index: str, rows: list[Row]):
        # одна вставка на всё окно: args собираются в плоский (текст, теги, текст, теги, …)
        args: list = []
        for r in rows:
            args.extend(self._line_chunks(r))
        if args:
            self.text.insert(index, *args)

    def _render(self, insns: list[core.Insn]):
        self.rows = self._make_rows(insns)
        t = self.text
        t.configure(state="normal")
        t.delete("1.0", "end")
        self._insert_rows("1.0", self.rows)
        t.delete("end-2c", "end-1c")  # убираем свой последний перевод строки
        t.configure(state="disabled")
        self._hover_line = None

    def _on_yscroll(self, first, last):
        self.scrollbar.set(first, last)
        if not self._extending and self.rows:
            self._extending = True
            self.after_idle(self._maybe_extend)

    def _maybe_extend(self):
        try:
            first, last = self.text.yview()
            if last >= 1 - EDGE:
                self._extend_down()
            elif first <= EDGE:
                self._extend_up()
        finally:
            self._extending = False

    def _extend_down(self):
        b = self.binary
        last = self.rows[-1].insn
        nxt = last.address + len(last.raw)
        sec = b.section_at(last.address)
        if sec is None or nxt >= sec.end:
            return
        new = self._make_rows(b.disassemble(nxt, CHUNK))
        if not new:
            return
        t = self.text
        t.configure(state="normal")
        t.insert("end", "\n")
        self._insert_rows("end", new)
        t.delete("end-2c", "end-1c")  # убираем свой последний перевод строки
        self.rows.extend(new)
        excess = len(self.rows) - MAX_ROWS
        if excess > 0:
            top = int(t.index("@0,0").split(".")[0])
            t.delete("1.0", f"{excess + 1}.0")
            del self.rows[:excess]
            t.yview(f"{max(1, top - excess)}.0")
            self._hover_line = None
        t.configure(state="disabled")
        self._highlight_current()

    def _extend_up(self):
        b = self.binary
        new = self._make_rows(b.disassemble_before(self.rows[0].insn.address, CHUNK))
        if not new:
            return
        t = self.text
        top = int(t.index("@0,0").split(".")[0])
        t.configure(state="normal")
        self._insert_rows("1.0", new)
        self.rows[:0] = new
        if len(self.rows) > MAX_ROWS:
            t.delete(f"{MAX_ROWS}.end", "end")
            del self.rows[MAX_ROWS:]
        t.configure(state="disabled")
        t.yview(f"{top + len(new)}.0")
        self._hover_line = None
        self._highlight_current()

    def _row_index(self, addr: int | None) -> int | None:
        if addr is None:
            return None
        for i, r in enumerate(self.rows):
            if r.label is None and r.insn.address == addr:
                return i
        return None

    def _center_on(self, row: int):
        t = self.text
        t.see(f"{row + 1}.0")
        visible = self._page()
        t.yview(f"{max(1, row + 1 - visible // 3)}.0")

    def _highlight_current(self):
        t = self.text
        t.tag_remove("current", "1.0", "end")
        row = self._row_index(self.cur_addr)
        if row is not None:
            t.tag_add("current", f"{row + 1}.0", f"{row + 2}.0")

    def _flash(self, row: int):
        """Короткая зелёная вспышка на строке, куда прыгнули, — глаз сразу её находит."""
        t = self.text
        if self._flash_job:
            self.after_cancel(self._flash_job)
        t.tag_remove("flash", "1.0", "end")
        t.tag_add("flash", f"{row + 1}.0", f"{row + 2}.0")
        steps = 28

        def step(i=0):
            if i > steps:
                t.tag_remove("flash", "1.0", "end")
                self._flash_job = None
                return
            t.tag_configure("flash", background=_lerp_color(COLOR_ACCENT_DIM, COLOR_ROW_CURRENT,
                                                            _ease_out(i / steps)))
            self._flash_job = self.after(FRAME_MS, step, i + 1)

        step()

    # ------------------------------------------------------------ мышь и лог

    def _line_at(self, event) -> int:
        return int(self.text.index(f"@{event.x},{event.y}").split(".")[0])

    def _on_text_click(self, event):
        self.text.focus_set()
        line = self._line_at(event)
        if 1 <= line <= len(self.rows):
            self.cur_addr = self.rows[line - 1].insn.address
            self._highlight_current()
            self._update_status_right()

    def _on_link_click(self, event):
        line = self._line_at(event)
        if 1 <= line <= len(self.rows):
            target = self.rows[line - 1].insn.target
            if target is not None:
                self.cur_addr = self.rows[line - 1].insn.address
                self.goto(target)
        return "break"

    def _on_motion(self, event):
        self._set_hover(self._line_at(event))

    def _set_hover(self, line):
        if line == self._hover_line:
            return
        t = self.text
        t.tag_remove("hover", "1.0", "end")
        if line is not None and 1 <= line <= len(self.rows):
            t.tag_add("hover", f"{line}.0", f"{line + 1}.0")
        self._hover_line = line

    def _on_zoom_wheel(self, event):
        self.zoom(+1 if event.delta > 0 else -1)
        return "break"

    def zoom(self, delta: int):
        size = max(8, min(24, self.mono.cget("size") + delta))
        self.mono.configure(size=size)
        self.mono_bold.configure(size=size)
        return "break"

    def copy_current(self):
        row = self._row_index(self.cur_addr)
        if row is not None:
            line = self.text.get(f"{row + 1}.0", f"{row + 1}.end").strip()
            self.clipboard_clear()
            self.clipboard_append(line)
            self._toast("Строка скопирована")
        return "break"

    # ------------------------------------------------------------ боковая панель

    def _on_section_pick(self, _event):
        sel = self.sec_list.curselection()
        if sel and self.binary:
            sec = self.binary.sections[sel[0]]
            if sec.data:
                self.goto(sec.vaddr)

    def _schedule_filter(self):
        # фильтруем не на каждую клавишу, а после короткой паузы в наборе
        if self._filter_job:
            self.after_cancel(self._filter_job)
        self._filter_job = self.after(120, self._apply_filter)

    def _apply_filter(self):
        self._filter_job = None
        needle = self.sym_filter.get().strip().lower()
        items = [(a, n) for a, n in self._sym_items if needle in n.lower()] if needle else self._sym_items
        self.sym_list.delete(0, "end")
        self.sym_list.insert("end", *[f"{a:>#12x}  {n}" for a, n in items[:20000]])
        self._sym_shown = [a for a, _ in items[:20000]]

    def _on_symbol_pick(self, _event):
        sel = self.sym_list.curselection()
        if sel:
            self.goto(self._sym_shown[sel[0]])

    def run_search(self):
        b = self.binary
        query = self.search_entry.get().strip()
        if b is None or not query:
            return
        mode = self.search_mode.get()
        if mode == "Байты":
            try:
                pattern = core.parse_hex_bytes(query)
            except ValueError as e:
                self._error(f"Байты: {e}")
                return

            def work():
                return [(a, "") for a in b.search_bytes(pattern)]
        else:
            def work():
                return [(i.address, f"{i.mnemonic} {i.op_str}") for i in b.search_text(query)]

        def done(hits, err):
            if err is not None:
                self._error(f"Поиск упал: {err!r}")
                return
            self._search_hits = [a for a, _ in hits]
            self.hit_list.delete(0, "end")
            self.hit_list.insert("end", *[f"{a:>#12x}  {s}" for a, s in hits])
            more = " (показаны первые)" if len(hits) >= 500 else ""
            self.search_info.configure(text=f"«{query}»: {len(hits)} совпадений{more}")
            self.side.set("Поиск")
            if hits:
                self.hit_list.selection_set(0)
                self.goto(hits[0][0])

        self.run_bg(work, done, f"Ищу «{query}»…")

    def _on_hit_pick(self, _event):
        sel = self.hit_list.curselection()
        if sel:
            self.goto(self._search_hits[sel[0]])

    # ---------------------------------------------------------------- статус

    def _update_status_left(self):
        b = self.binary
        if b is None:
            self.status_left.configure(text="Файл не открыт", text_color=COLOR_MUTED)
            return
        exe = sum(s.executable for s in b.sections)
        self.status_left.configure(
            text=f"{b.path.name}   ·   {b.fmt}   ·   {b.arch_name}   ·   "
                 f"{len(b.sections)} секций ({exe} исп.)   ·   {len(b.symbols)} символов",
            text_color=COLOR_MUTED)

    def _update_status_right(self):
        b = self.binary
        if b is None or self.cur_addr is None:
            self.status_right.configure(text="")
            return
        sec = b.section_at(self.cur_addr)
        sym = b.symbol_for(self.cur_addr)
        parts = [f"{self.cur_addr:#x}"]
        if sec:
            parts.append(sec.name)
        if sym:
            parts.append(sym)
        self.status_right.configure(text="   ".join(parts))

    def _update_nav_buttons(self):
        self.btn_back.configure(state="normal" if self.back else "disabled")
        self.btn_fwd.configure(state="normal" if self.forward else "disabled")

    def _error(self, msg: str):
        self._toast(msg, error=True)

    def _toast(self, msg: str, error: bool = False):
        """Всплывашка в правом нижнем углу листинга: плавно проявляется и сама уходит."""
        old = getattr(self, "_toast_widget", None)
        if old is not None:
            old.destroy()
        color = COLOR_ERROR if error else COLOR_ACCENT
        w = ctk.CTkLabel(self.card, text=f"  {msg}  ", fg_color=COLOR_CARD, corner_radius=8,
                         text_color=COLOR_BG, height=34)
        self._toast_widget = w
        w.place(relx=1.0, rely=1.0, x=-24, y=-18, anchor="se")
        w.lift()
        steps = 10

        def fade(i, direction):
            if not w.winfo_exists():
                return
            k = _ease_out(i / steps)
            w.configure(text_color=_lerp_color(COLOR_CARD, color, k if direction > 0 else 1 - k))
            if i < steps:
                self.after(FRAME_MS, fade, i + 1, direction)
            elif direction > 0:
                self.after(2600 if error else 1400, fade, 0, -1)
            else:
                w.destroy()

        fade(0, +1)


def main():
    app = App()
    if len(sys.argv) > 1:
        app.after(100, app.open_path, sys.argv[1])
    app.mainloop()


if __name__ == "__main__":
    main()
