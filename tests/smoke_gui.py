"""
Смоук-тест интерфейса: открыть бинарник, дождаться листинга, прокрутить
вниз (догрузка), перейти по первому call и закрыть окно. Нужен дисплей,
поэтому гоняется только на Windows-раннере, а не в pytest.

  python tests/smoke_gui.py C:\\Windows\\System32\\notepad.exe
"""

import sys
from pathlib import Path

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
            result.update(ok=True, msg=f"{app.binary.fmt} {app.binary.arch_name}: "
                                       f"{first} строк сразу, {scrolled} после прокрутки, переход по call ок")
        except AssertionError as e:
            result["msg"] = f"FAIL: {e}"
        app.destroy()

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
