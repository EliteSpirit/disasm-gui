import pytest

gui = pytest.importorskip("gui", reason="нужны tkinter и customtkinter", exc_type=ImportError)

CTRL, ALT = 0x4, gui.WIN_ALT_MASK


@pytest.mark.parametrize("keysym,keycode,state,expected", [
    ("Cyrillic_a", 70, CTRL, "f"),  # Ctrl+F в русской раскладке
    ("??", 67, CTRL, "c"),  # Tk не знает keysym, но код клавиши VK_C есть всегда
    ("f", 70, CTRL, None),  # обычная латиница — её разбирают свои привязки
    ("EuroSign", 69, CTRL | ALT, None),  # AltGr+E в немецкой раскладке
    ("Up", 38, CTRL, None),
])
def test_ctrl_letter_windows(keysym, keycode, state, expected):
    assert gui.ctrl_letter(keysym, keycode, state, "win32") == expected


@pytest.mark.parametrize("keysym,expected", [("Cyrillic_es", "c"), ("Cyrillic_shcha", "o"), ("f", None)])
def test_ctrl_letter_x11(keysym, expected):
    assert gui.ctrl_letter(keysym, 0, CTRL, "x11") == expected
