"""JavaScript beautifier.

Uses the `jsbeautifier` package when available for high-quality output, and
otherwise falls back to a lightweight built-in re-indenter so the tool works
with zero third-party dependencies.

The fallback is intentionally simple: it inserts newlines around block
delimiters and statement terminators and re-indents. It is good enough to make
minified one-liners human-readable and, crucially, to put interesting tokens on
their own lines so line-numbered context is meaningful.
"""

try:
    import jsbeautifier  # type: ignore
    _HAVE_JSB = True
except Exception:  # pragma: no cover - import guard
    _HAVE_JSB = False


def beautify(code: str) -> str:
    """Return a pretty-printed version of *code*."""
    if _HAVE_JSB:
        opts = jsbeautifier.default_options()
        opts.indent_size = 2
        opts.max_preserve_newlines = 2
        opts.space_in_empty_paren = False
        try:
            return jsbeautifier.beautify(code, opts)
        except Exception:
            pass  # fall through to the built-in
    return _fallback_beautify(code)


def _fallback_beautify(code: str) -> str:
    """A tiny string-aware re-indenter. Not a parser — best effort only."""
    out = []
    indent = 0
    i = 0
    n = len(code)
    in_str = None          # current quote char, or None
    escaped = False
    line_has_content = False

    def nl():
        out.append("\n" + ("  " * max(indent, 0)))

    while i < n:
        c = code[i]

        # Inside a string / template literal: copy verbatim.
        if in_str:
            out.append(c)
            if escaped:
                escaped = False
            elif c == "\\":
                escaped = True
            elif c == in_str:
                in_str = None
            i += 1
            continue

        # Preserve line & block comments verbatim (do not reflow their guts).
        if c == "/" and i + 1 < n and code[i + 1] == "/":
            j = code.find("\n", i)
            j = n if j == -1 else j
            out.append(code[i:j])
            nl()                       # terminate the line comment
            line_has_content = False
            i = j
            continue
        if c == "/" and i + 1 < n and code[i + 1] == "*":
            j = code.find("*/", i + 2)
            j = n if j == -1 else j + 2
            out.append(code[i:j])
            i = j
            continue

        if c in "\"'`":
            in_str = c
            out.append(c)
            line_has_content = True
            i += 1
            continue

        if c in "{[":
            out.append(c)
            indent += 1
            nl()
            line_has_content = False
            i += 1
            # swallow following whitespace
            while i < n and code[i] in " \t\r\n":
                i += 1
            continue

        if c in "}]":
            indent -= 1
            if line_has_content:
                nl()
            else:
                # replace trailing indent with the dedented one
                _trim_trailing_indent(out)
                out.append("  " * max(indent, 0))
            out.append(c)
            line_has_content = True
            i += 1
            continue

        if c == ";":
            out.append(c)
            nl()
            line_has_content = False
            i += 1
            while i < n and code[i] in " \t\r\n":
                i += 1
            continue

        if c in "\r\n":
            i += 1
            continue

        if c in " \t":
            if line_has_content:
                out.append(" ")
            i += 1
            # collapse runs of whitespace
            while i < n and code[i] in " \t":
                i += 1
            continue

        out.append(c)
        line_has_content = True
        i += 1

    text = "".join(out)
    # tidy: drop leading blank, collapse >2 blank lines
    lines = [ln.rstrip() for ln in text.split("\n")]
    cleaned = []
    blanks = 0
    for ln in lines:
        if ln.strip() == "":
            blanks += 1
            if blanks > 1:
                continue
        else:
            blanks = 0
        cleaned.append(ln)
    return "\n".join(cleaned).strip() + "\n"


def _trim_trailing_indent(out):
    """Remove the whitespace-only indent at the tail of *out* (from last nl())."""
    while out and out[-1].strip() == "" and out[-1] != "\n":
        out.pop()
    # out[-1] is now "\n..." from nl(); strip its indent portion
    if out and out[-1].startswith("\n"):
        out[-1] = "\n"
