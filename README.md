# Disasm GUI

Тёмный графический дизассемблер на Python: CustomTkinter для интерфейса, [Capstone](https://www.capstone-engine.org/) для разбора инструкций. Внешне в том же стиле, что и [zapret-gui](https://github.com/EliteSpirit/zapret-gui).

Это не IDA и не Ghidra: нет декомпилятора, графа функций и анализа перекрёстных ссылок. Задача другая — быстро открыть бинарник и полистать код, не запуская ничего тяжёлого.

## Что умеет

- **Форматы:** PE (`.exe`, `.dll`), ELF, сырой дамп. Для дампа при открытии спрашивает архитектуру и базовый адрес.
- **Архитектуры:** x86 (16/32/64), ARM, ARM Thumb, ARM64, MIPS32 (LE/BE), RISC-V 64. У ARM ELF режим Thumb определяется сам по точке входа, но один на весь файл: смешанный ARM/Thumb-код в одном бинарнике частично покажется мусором.
- **Символы:** импорты и экспорты PE, `symtab`/`dynsym` ELF (включая IFUNC вроде `memcpy` в glibc). Заглушки `.plt`, `.plt.sec`, `.plt.got` и слоты GOT подписаны именами импортов (`printf@plt`, `stdout@got`).
- **Листинг** с подсветкой: `call`, условные и безусловные переходы, `ret` выделены разными цветами. Для `[rip + X]` и абсолютных адресов в комментарии показан итоговый адрес, а если там импорт, то его имя (`KERNEL32!ExitProcess`, `__libc_start_main@got`).
- **Навигация:** клик по адресу в `call`/`jmp` переносит туда, есть история «назад/вперёд» и переход по адресу или имени символа.
- **Поиск** по тексту инструкций (`mov rax`, `syscall`) и по байтам (`0f 05`, `\x48\x8b`), результаты открываются в отдельной вкладке.

## Почему не тормозит

- Загрузка файла и поиск по всему бинарнику идут в фоновом потоке. Пока они работают, под тулбаром бежит тонкая полоска, а окно остаётся живым.
- В листинге одновременно не больше 4000 строк. Остальное догружается кусками по 600 инструкций, когда докручиваешь до края, а дальний конец обрезается. Поэтому секция `.text` на десятки мегабайт открывается так же быстро, как маленькая.
- Списки символов и результатов сделаны на обычном `tk.Listbox`, а не на сотнях CTk-виджетов. Фильтр срабатывает после паузы в наборе, а не на каждую клавишу.
- После перехода строка коротко вспыхивает зелёным, чтобы глаз сразу её нашёл. Ошибки показываются всплывашкой в углу, а не модальным окном.

## Запуск

```bash
pip install -r requirements.txt
python gui.py              # или сразу: python gui.py путь/к/файлу.exe
```

Нужен Python 3.9+ с tkinter (в официальном установщике для Windows он есть по умолчанию).

## Горячие клавиши

| Клавиши | Действие |
| --- | --- |
| `Ctrl+O` | открыть файл |
| `Ctrl+G` | перейти к адресу или символу (`0x401000`, `401000h`, `main`) |
| `Ctrl+F` | поиск |
| `Enter` | перейти по `call`/`jmp` в текущей строке |
| `Esc`, `Alt+←` / `Alt+→` | назад / вперёд |
| `↑ ↓ PgUp PgDn` | ходить по строкам |
| `Ctrl+C` | скопировать строку |
| `Ctrl+колесо`, `Ctrl+=`, `Ctrl+-` | размер шрифта |

Сочетания с `Ctrl` работают и в русской раскладке, включая `Ctrl+C`/`Ctrl+V` в полях ввода.

## Сборка в .exe

Запусти `build.bat`, результат появится в `dist\DisasmGUI.exe`.

## Структура

- `disasm_core.py` — загрузчики PE/ELF/raw, дизассемблирование, символы, поиск. Без tkinter, можно использовать из консоли.
- `gui.py` — интерфейс.
- `tests/` — тесты (`python -m pytest`) и смоук-тест окна `tests/smoke_gui.py`: ему нужен дисплей, на Linux без него запускай через `xvfb-run -a python tests/smoke_gui.py /bin/ls`.

## Code signing policy

Free code signing provided by [SignPath.io](https://about.signpath.io/), certificate by [SignPath Foundation](https://signpath.org/).

Windows releases (`DisasmGUI.exe`) are built from this repository by the [Release workflow](.github/workflows/release.yml) on GitHub Actions and signed only after manual approval.

Team roles:

- Committers and reviewers: [EliteSpirit](https://github.com/EliteSpirit)
- Approvers: [EliteSpirit](https://github.com/EliteSpirit)

### Privacy policy

This program will not transfer any information to other networked systems unless specifically requested by the user or the person installing or operating it. Disasm GUI has no network code at all: it only reads the files you open.

## Лицензия

MIT, см. [LICENSE](LICENSE).
