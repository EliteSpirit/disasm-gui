"""
Смоук-тест интерфейса: открыть бинарник, дождаться листинга, прокрутить
вниз (догрузка), перейти по call с клавиатуры и кликом мыши, нажать Ctrl+F
в русской раскладке и закрыть окно. Нужен дисплей, поэтому в CI гоняется
на Windows-раннере и под Xvfb на Linux, а не в pytest.

  python tests/smoke_gui.py C:\\Windows\\System32\\notepad.exe
"""

import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import gui  # noqa: E402

TIMEOUT_MS = 60_000
result = {"ok": False, "msg": "таймаут: файл так и не загрузился"}


def main(path: str) -> int:
    app = gui.App()

    def check():
        if app.binary is None:
            app.after(100, check)
            return
        app.after(500, verify)  # даём окну отрисоваться, иначе прокрутка ничего не делает

    def verify():
        try:
            assert app.rows, "листинг пустой"
            first = len(app.rows)
            for _ in range(40):
                app.text.yview_scroll(30, "units")
                app.update()
            scrolled = len(app.rows)
            addrs = [r.insn.address for r in app.rows if r.label is None]
            assert scrolled > first, "при прокрутке листинг не догрузился"
            assert all(a < b for a, b in zip(addrs, addrs[1:])), "адреса в листинге не по порядку"
            call = next((r.insn for r in app.rows if r.insn.group == "call" and r.insn.target), None)
            if call is not None:
                app.cur_addr = call.address
                app.follow_current()
                app.update()
                assert app.cur_addr == call.target, "переход по call не сработал"
                app.go_back()
                app.update()
            clicked = click_link()
            ctrl_f_in_russian_layout()
            click = "ок" if clicked else "не проверен: ссылок не видно"
            result.update(ok=True, msg=f"{app.binary.fmt} {app.binary.arch_name}: {first} строк сразу, "
                                       f"{scrolled} после прокрутки, переход по call ок, "
                                       f"клик по ссылке {click}, Ctrl+F в русской раскладке ок")
        except Exception as e:  # noqa: BLE001 — любая ошибка должна дать FAIL, а не таймаут
            result["msg"] = f"FAIL: {e!r}"
        app.destroy()

    def click_link() -> bool:
        """Клик мышью по операнду call/jmp: текущей строкой должна стать цель перехода."""
        t = app.text
        for i, r in enumerate(app.rows):
            rng = t.tag_nextrange("link", f"{i + 1}.0", f"{i + 1}.end")
            box = t.bbox(rng[0]) if rng else None
            if box is None:
                continue
            x, y = box[0] + 2, box[1] + box[3] // 2
            t.event_generate("<ButtonPress-1>", x=x, y=y)
            t.event_generate("<ButtonRelease-1>", x=x, y=y)
            app.update()
            assert app.cur_addr == r.insn.target, (
                f"после клика по ссылке текущая строка {app.cur_addr:#x}, а не цель {r.insn.target:#x}")
            app.go_back()
            app.update()
            return True
        return False

    def ctrl_f_in_russian_layout():
        # Сымитировать нажатие в чужой раскладке нельзя: keysym, которого нет в текущей раскладке,
        # event_generate отдаёт как «??». Поэтому обработчику подаём событие в том виде, в каком
        # его присылает Tk (кириллический keysym, код клавиши VK_F), а дальше всё настоящее:
        # перевыпуск <Control-f> и привязка, которая ставит фокус в поиск
        focused = []
        focus_entry = app._focus_entry
        app._focus_entry = lambda entry: focused.append(entry) or focus_entry(entry)
        event = SimpleNamespace(widget=app.text, keysym="Cyrillic_a", keycode=70, state=0x4)
        assert app._on_ctrl_nonlatin(event) == "break", "Ctrl+F в русской раскладке не распознан"
        app.update()
        app._focus_entry = focus_entry
        assert focused == [app.search_entry], "Ctrl+F в русской раскладке не открыл поиск"

    app.after(50, app.open_path, path)
    app.after(100, check)
    app.after(TIMEOUT_MS, app.destroy)
    app.mainloop()
    print(result["msg"])
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    # консоль Windows-раннера в cp1252 и падает на кириллице в print
    sys.stdout.reconfigure(encoding="utf-8")
    sys.exit(main(sys.argv[1]))
