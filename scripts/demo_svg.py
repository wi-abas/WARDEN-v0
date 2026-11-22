"""Render the demo's output as a terminal-style SVG for the README.

Run:  uv run python scripts/demo_svg.py   (writes docs/demo.svg)
"""

import contextlib
import importlib.util
import io
import re
from html import escape
from pathlib import Path

ROOT = Path(__file__).parent.parent
COLORS = {"32": "#4ade80", "31": "#f87171", "33": "#facc15"}
DEFAULT = "#e5e7eb"
CHAR_W, LINE_H, PAD = 8.4, 19, 20


def demo_output() -> str:
    spec = importlib.util.spec_from_file_location("demo", ROOT / "examples" / "demo.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("can't load examples/demo.py")
    demo = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(demo)
    demo.USE_COLOR = True
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        demo.run()
    # Times change on every run; pin them so the image only changes when the demo does.
    return re.sub(r"\b\d\d:\d\d:\d\d\b", "12:00:00", buffer.getvalue().strip("\n"))


def line_to_tspans(line: str) -> str:
    parts, color = [], DEFAULT
    for chunk in re.split(r"(\033\[\d+m)", line):
        code = re.fullmatch(r"\033\[(\d+)m", chunk)
        if code:
            color = COLORS.get(code.group(1), DEFAULT)
        elif chunk:
            weight = ' font-weight="bold"' if color != DEFAULT else ""
            parts.append(f'<tspan fill="{color}"{weight}>{escape(chunk)}</tspan>')
    return "".join(parts)


def render(text: str) -> str:
    lines = ["$ uv run python examples/demo.py", "", *text.split("\n")]
    plain = [re.sub(r"\033\[\d+m", "", line) for line in lines]
    width = int(max(len(line) for line in plain) * CHAR_W + 2 * PAD)
    height = int(len(lines) * LINE_H + 2 * PAD + 24)
    rows = [
        f'<text x="{PAD}" y="{PAD + 24 + (i + 1) * LINE_H}" xml:space="preserve">'
        f"{line_to_tspans(line)}</text>"
        for i, line in enumerate(lines)
    ]
    return "\n".join(
        [
            f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
            f'viewBox="0 0 {width} {height}" font-family="ui-monospace, SFMono-Regular, '
            f'Menlo, Consolas, monospace" font-size="14">',
            f'<rect width="{width}" height="{height}" rx="10" fill="#111827"/>',
            '<circle cx="22" cy="20" r="6" fill="#f87171"/>',
            '<circle cx="42" cy="20" r="6" fill="#facc15"/>',
            '<circle cx="62" cy="20" r="6" fill="#4ade80"/>',
            *rows,
            "</svg>",
            "",
        ]
    )


if __name__ == "__main__":
    out = ROOT / "docs" / "demo.svg"
    out.write_text(render(demo_output()), encoding="utf-8")
    print(f"wrote {out}")
