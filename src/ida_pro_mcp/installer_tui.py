import sys


def _enable_win_vt() -> bool:
    """Enable ANSI/VT escape sequence processing on Windows 10+.

    Returns True if ANSI codes are supported, False otherwise.
    """
    if sys.platform != "win32":
        return True
    try:
        import ctypes
        k32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        handle = k32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.c_ulong()
        if not k32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        # ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
        if not k32.SetConsoleMode(handle, mode.value | 0x0004):
            return False
        return True
    except Exception:
        return False


_ANSI = _enable_win_vt()

# When ANSI is unsupported, strip escape codes from display strings.
_BOLD = "\033[1m" if _ANSI else ""
_RESET = "\033[0m" if _ANSI else ""
_CYAN = "\033[36m" if _ANSI else ""
_GREEN = "\033[32m" if _ANSI else ""
_HIDE_CURSOR = "\033[?25l" if _ANSI else ""
_SHOW_CURSOR = "\033[?25h" if _ANSI else ""


def _make_read_key():
    if not sys.stdin.isatty():
        return None
    try:
        if sys.platform == "win32":
            import msvcrt

            def read_key():
                ch = msvcrt.getwch()
                if ch in ("\x00", "\xe0"):
                    ch2 = msvcrt.getwch()
                    if ch2 == "H":
                        return "up"
                    if ch2 == "P":
                        return "down"
                    return None
                if ch == " ":
                    return "space"
                if ch == "\r":
                    return "enter"
                if ch == "\x1b":
                    return "esc"
                if ch == "a":
                    return "a"
                return None
        else:
            import termios
            import tty

            def read_key():
                fd = sys.stdin.fileno()
                old = termios.tcgetattr(fd)
                try:
                    tty.setraw(fd)
                    ch = sys.stdin.read(1)
                    if ch == "\x1b":
                        ch2 = sys.stdin.read(1)
                        if ch2 == "[":
                            ch3 = sys.stdin.read(1)
                            if ch3 == "A":
                                return "up"
                            if ch3 == "B":
                                return "down"
                        return "esc"
                    if ch == " ":
                        return "space"
                    if ch in ("\r", "\n"):
                        return "enter"
                    if ch == "a":
                        return "a"
                    if ch == "\x03":
                        return "esc"
                    return None
                finally:
                    termios.tcsetattr(fd, termios.TCSADRAIN, old)

        return read_key
    except ImportError:
        return None


def _tui_loop(read_key, render, on_key) -> bool:
    sys.stdout.write(_HIDE_CURSOR)
    output = render()
    sys.stdout.write(output + "\n")
    sys.stdout.flush()
    total_lines = output.count("\n") + 1

    def clear():
        sys.stdout.write(f"\033[{total_lines}A\033[J")
        sys.stdout.flush()

    try:
        while True:
            key = read_key()
            result = on_key(key)
            if result == "confirm":
                clear()
                return True
            if result == "cancel":
                clear()
                return False
            if result == "noop":
                continue

            clear()
            output = render()
            sys.stdout.write(output + "\n")
            sys.stdout.flush()
            total_lines = output.count("\n") + 1
    finally:
        sys.stdout.write(_SHOW_CURSOR)
        sys.stdout.flush()


def interactive_choose(items: list[str], title: str, default: int = 0) -> str | None:
    read_key = _make_read_key()
    if read_key is None:
        return None

    cursor = default

    def render():
        lines = [f"{_BOLD}{title}{_RESET}"]
        lines.append("  (up/down: move, enter: confirm, esc: cancel)")
        lines.append("")
        for i, name in enumerate(items):
            pointer = f"{_CYAN}>{_RESET}" if i == cursor else " "
            lines.append(f"  {pointer} {name}")
        return "\n".join(lines)

    def on_key(key):
        nonlocal cursor
        if key == "up":
            cursor = (cursor - 1) % len(items)
        elif key == "down":
            cursor = (cursor + 1) % len(items)
        elif key in ("enter", "space"):
            return "confirm"
        elif key == "esc":
            return "cancel"
        else:
            return "noop"
        return "redraw"

    if _tui_loop(read_key, render, on_key):
        result = items[cursor]
        print(f"{_BOLD}{title}{_RESET} {result}")
        return result
    return None


def interactive_select(items: list[tuple[str, bool]], title: str) -> list[str] | None:
    read_key = _make_read_key()
    if read_key is None:
        return None

    selected = [checked for _, checked in items]
    cursor = 0

    def render():
        lines = [f"{_BOLD}{title}{_RESET}"]
        lines.append("  (space: toggle, a: toggle all, enter: confirm, esc: cancel)")
        lines.append("")
        for i, (name, _) in enumerate(items):
            check = f"{_GREEN}[x]{_RESET}" if selected[i] else "[ ]"
            pointer = f"{_CYAN}>{_RESET}" if i == cursor else " "
            lines.append(f"  {pointer} {check} {name}")
        return "\n".join(lines)

    def on_key(key):
        nonlocal cursor, selected
        if key == "up":
            cursor = (cursor - 1) % len(items)
        elif key == "down":
            cursor = (cursor + 1) % len(items)
        elif key == "space":
            selected[cursor] = not selected[cursor]
        elif key == "a":
            all_selected = all(selected)
            selected = [not all_selected] * len(items)
        elif key == "enter":
            return "confirm"
        elif key == "esc":
            return "cancel"
        else:
            return "noop"
        return "redraw"

    if _tui_loop(read_key, render, on_key):
        result = [name for (name, _), sel in zip(items, selected) if sel]
        if result:
            print(f"{_BOLD}{title}{_RESET} {', '.join(result)}")
        else:
            print(f"{_BOLD}{title}{_RESET} (none)")
        return result
    return None
