#!/usr/bin/env python3
"""
StaticElf — ELF Binary Static Analysis CLI
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
A command-line tool for analyzing ELF binaries using the elfanalyzer library.

Usage:
    python staticelf.py <binary> [options]
    python staticelf.py --diff <binary_a> <binary_b> [--out-file report.html]

Examples:
    # Full analysis, pretty-print to terminal
    python staticelf.py /bin/ls

    # Only show hashes and security features
    python staticelf.py /bin/ls --hashes --security

    # Export to JSON
    python staticelf.py /bin/ls --output json --out-file results.json

    # Export to CSV (pandas-ready, one row per binary)
    python staticelf.py /bin/ls --output csv --out-file features.csv

    # Export to NumPy .npz
    python staticelf.py /bin/ls --output npz --out-file features.npz

    # Diff two binaries — terminal output
    python staticelf.py --diff /bin/ls.old /bin/ls.new

    # Diff two binaries — HTML report saved to file
    python staticelf.py --diff /bin/ls.old /bin/ls.new --out-file diff.html
"""

import sys
import os
import math
import json
import argparse
from pathlib import Path

try:
    from elfanalyzer import ELFAnalyzer
except ImportError:
    print("[!] Could not import elfanalyzer. Make sure elfanalyzer.py is in the same directory.", file=sys.stderr)
    sys.exit(1)

# Optional ASM analysis (requires capstone + asmanalyzer.py)
try:
    from asmanalyzer import ASMAnalyzer, WLKernel, capstone_available as _cs_avail
    _CAPSTONE = _cs_avail()
except ImportError:
    _CAPSTONE = False
    ASMAnalyzer = WLKernel = None

# ------------------------------------------------------------------ #
#  ANSI colors                                                         #
# ------------------------------------------------------------------ #

RESET  = "\033[0m"
BOLD   = "\033[1m"
GREEN  = "\033[32m"
YELLOW = "\033[33m"
CYAN   = "\033[36m"
RED    = "\033[31m"
DIM    = "\033[2m"

# Mutable mapping so we can disable colors without touching globals
_C = {
    "RESET": RESET, "BOLD": BOLD, "GREEN": GREEN,
    "YELLOW": YELLOW, "CYAN": CYAN, "RED": RED, "DIM": DIM,
}

def _disable_color():
    for k in _C:
        _C[k] = ""

def _color(text, code):
    return f"{code}{text}{_C['RESET']}"

def _header(title):
    bar = "─" * (len(title) + 4)
    print(f"\n{_color(f'┌{bar}┐', _C['CYAN'])}")
    print(f"{_color('│', _C['CYAN'])}  {_color(title, _C['BOLD'])}  {_color('│', _C['CYAN'])}")
    print(f"{_color(f'└{bar}┘', _C['CYAN'])}")

def _kv(key, value, indent=2):
    pad = " " * indent
    print(f"{pad}{_color(key + ':', _C['DIM'])} {value}")

def _bool_badge(value: bool) -> str:
    return _color("✔  YES", _C['GREEN']) if value else _color("✘  NO", _C['RED'])


# ------------------------------------------------------------------ #
#  Standard analysis print functions                                   #
# ------------------------------------------------------------------ #

def print_architecture(az: ELFAnalyzer):
    _header("Architecture")
    arch = az.arch
    _kv("Machine     ", _color(arch.get("machine", "?"), _C['YELLOW']))
    _kv("Bits        ", str(arch.get("bits", "?")))
    _kv("Endianness  ", arch.get("endianness", "?"))
    _kv("ABI         ", arch.get("abi", "?"))
    _kv("ELF Type    ", arch.get("elf_type", "?"))
    _kv("Entry Point ", _color(arch.get("entry_point", "?"), _C['CYAN']))

def print_summary(az: ELFAnalyzer):
    path  = az.path
    size  = f"{az.file_size:,} bytes"
    link  = _color(az.static.upper(), _C['YELLOW'])
    arch  = _color(f"{az.arch.get('machine','?')} {az.arch.get('bits','?')}-bit {az.arch.get('endianness','?')}-endian", _C['GREEN'])
    md5   = az.hashes.get("md5", "?")[:16] + "..."
    print(f"\n{_color('◆ StaticElf', _C['BOLD'])}  {_color(path, _C['CYAN'])}")
    print(f"  Size: {size}   Arch: {arch}   Linking: {link}   MD5: {_color(md5, _C['DIM'])}")

def print_hashes(az: ELFAnalyzer):
    _header("Hashes")
    _kv("MD5   ", az.hashes.get("md5", "n/a"))
    _kv("SHA256", az.hashes.get("sha256", "n/a"))

def print_security(az: ELFAnalyzer):
    _header("Security Features")
    sec = az.security
    _kv("NX (non-exec stack)", _bool_badge(sec.get("nx", False)))
    _kv("PIE                ", _bool_badge(sec.get("pie", False)))
    _kv("Stack Canary       ", _bool_badge(sec.get("canary", False)))
    _kv("FORTIFY            ", _bool_badge(sec.get("fortify", False)))
    _kv("Debug Symbols      ", _bool_badge(sec.get("debug", False)))
    _kv("Stripped           ", _bool_badge(sec.get("stripped", False)))
    relro = sec.get("relro", "none")
    relro_color = _C['GREEN'] if relro == "full" else (_C['YELLOW'] if relro == "partial" else _C['RED'])
    _kv("RELRO              ", _color(relro.upper(), relro_color))

def print_sections(az: ELFAnalyzer):
    _header(f"Sections  ({len(az.sections)} total)")
    fmt = "  {:<24} {:<18} {:>10}  {}"
    print(_color(fmt.format("Name", "Type", "Size", "Flags"), _C['DIM']))
    print(_color("  " + "─" * 62, _C['DIM']))
    for s in az.sections:
        print(fmt.format(s["name"] or "<unnamed>", s["type"], f"{s['size']:,}", s["flags"]))

def print_imports(az: ELFAnalyzer):
    _header(f"Imports  ({len(az.imports)} symbols)")
    fmt = "  {:<40} {:<16} {}"
    print(_color(fmt.format("Name", "Type", "Binding"), _C['DIM']))
    print(_color("  " + "─" * 62, _C['DIM']))
    for imp in sorted(az.imports, key=lambda x: x["name"]):
        print(fmt.format(imp["name"], imp["type"], imp["binding"]))

def print_entropy(az: ELFAnalyzer):
    _header("Entropy  (bits/byte, 0.0 - 8.0)")
    whole = az.entropy.get("_whole_binary", 0.0)
    flag  = _color("  WARNING: HIGH - possible packing/encryption", _C['YELLOW']) if whole >= 7.0 else ""
    _kv("Whole binary", f"{whole:.6f}{flag}")
    key_sections = [".text", ".data", ".rodata", ".bss", ".plt", ".got"]
    print()
    for name in key_sections:
        val = az.entropy.get(name)
        if val is not None:
            bar  = "|" * int(val)
            flag = _color(" WARN", _C['YELLOW']) if val >= 7.0 else ""
            _kv(f"{name:<12}", f"{val:.6f}  {_color(bar, _C['CYAN'])}{flag}")

def print_strings(az: ELFAnalyzer, limit: int = 40):
    _header(f"Strings  ({len(az.strings)} found, showing up to {limit})")
    for s in sorted(az.strings)[:limit]:
        print(f"  {s}")
    if len(az.strings) > limit:
        print(_color(f"  ... {len(az.strings) - limit} more (use --strings-limit to show more)", _C['DIM']))


# ------------------------------------------------------------------ #
#  Diff engine                                                         #
# ------------------------------------------------------------------ #

def compute_diff(a: ELFAnalyzer, b: ELFAnalyzer) -> dict:
    """
    Compute a structured diff between two analyzed ELF binaries.
    Returns a dict with sections: hashes, file_size, sections, imports, entropy, strings.
    """
    diff = {}

    # Hashes
    diff["hashes"] = {
        "a": a.hashes,
        "b": b.hashes,
        "identical": a.hashes == b.hashes,
    }

    # File size
    diff["file_size"] = {
        "a": a.file_size,
        "b": b.file_size,
        "delta": b.file_size - a.file_size,
    }

    # Sections
    secs_a = {s["name"]: s for s in a.sections}
    secs_b = {s["name"]: s for s in b.sections}
    names_a, names_b = set(secs_a), set(secs_b)

    sections_added   = [secs_b[n] for n in sorted(names_b - names_a)]
    sections_removed = [secs_a[n] for n in sorted(names_a - names_b)]
    sections_changed = []
    for name in sorted(names_a & names_b):
        sa, sb = secs_a[name], secs_b[name]
        if sa["size"] != sb["size"] or sa["flags"] != sb["flags"]:
            sections_changed.append({
                "name":       name,
                "size_a":     sa["size"],
                "size_b":     sb["size"],
                "size_delta": sb["size"] - sa["size"],
                "flags_a":    sa["flags"],
                "flags_b":    sb["flags"],
            })

    diff["sections"] = {
        "added":   sections_added,
        "removed": sections_removed,
        "changed": sections_changed,
        "count_a": len(a.sections),
        "count_b": len(b.sections),
    }

    # Imports
    imps_a = {i["name"] for i in a.imports}
    imps_b = {i["name"] for i in b.imports}
    diff["imports"] = {
        "added":   sorted(imps_b - imps_a),
        "removed": sorted(imps_a - imps_b),
        "count_a": len(a.imports),
        "count_b": len(b.imports),
    }

    # Entropy
    all_entropy_keys = set(a.entropy) | set(b.entropy)
    entropy_changes = []
    for key in sorted(all_entropy_keys):
        va = a.entropy.get(key, 0.0)
        vb = b.entropy.get(key, 0.0)
        delta = round(vb - va, 6)
        if abs(delta) >= 0.01:
            entropy_changes.append({
                "section": key,
                "a":       va,
                "b":       vb,
                "delta":   delta,
            })
    diff["entropy"] = {
        "whole_a":     a.entropy.get("_whole_binary", 0.0),
        "whole_b":     b.entropy.get("_whole_binary", 0.0),
        "whole_delta": round(b.entropy.get("_whole_binary", 0.0) - a.entropy.get("_whole_binary", 0.0), 6),
        "changes":     entropy_changes,
    }

    # Strings
    strs_a = set(a.strings)
    strs_b = set(b.strings)
    diff["strings"] = {
        "added":   sorted(strs_b - strs_a),
        "removed": sorted(strs_a - strs_b),
        "count_a": len(a.strings),
        "count_b": len(b.strings),
    }

    return diff


# ------------------------------------------------------------------ #
#  Terminal diff output                                                #
# ------------------------------------------------------------------ #

def print_diff(a: ELFAnalyzer, b: ELFAnalyzer, diff: dict, strings_limit: int = 30):
    pa = Path(a.path).name
    pb = Path(b.path).name

    print(f"\n{_color('◆ StaticElf Diff', _C['BOLD'])}")
    print(f"  {_color('A:', _C['DIM'])} {_color(a.path, _C['CYAN'])}")
    print(f"  {_color('B:', _C['DIM'])} {_color(b.path, _C['CYAN'])}")

    # Hashes
    _header("Hashes")
    h = diff["hashes"]
    match = _color("✔  IDENTICAL", _C['GREEN']) if h["identical"] else _color("✘  DIFFERENT", _C['RED'])
    print(f"  {match}")
    _kv(f"MD5    [{pa}]", h["a"].get("md5", "?"))
    _kv(f"MD5    [{pb}]", h["b"].get("md5", "?"))
    _kv(f"SHA256 [{pa}]", h["a"].get("sha256", "?"))
    _kv(f"SHA256 [{pb}]", h["b"].get("sha256", "?"))

    fs = diff["file_size"]
    delta_str   = f"{fs['delta']:+,} bytes"
    delta_color = _C['GREEN'] if fs["delta"] < 0 else (_C['RED'] if fs["delta"] > 0 else _C['DIM'])
    _kv("File size A  ", f"{fs['a']:,} bytes")
    _kv("File size B  ", f"{fs['b']:,} bytes  ({_color(delta_str, delta_color)})")

    # Sections
    s = diff["sections"]
    _header(f"Sections  (A: {s['count_a']}  ->  B: {s['count_b']})")
    if s["added"]:
        print(f"  {_color('ADDED', _C['GREEN'])} ({len(s['added'])})")
        for sec in s["added"]:
            print(f"    {_color('+', _C['GREEN'])} {sec['name']:<24} {sec['type']:<18} {sec['size']:,} bytes")
    if s["removed"]:
        print(f"  {_color('REMOVED', _C['RED'])} ({len(s['removed'])})")
        for sec in s["removed"]:
            print(f"    {_color('-', _C['RED'])} {sec['name']:<24} {sec['type']:<18} {sec['size']:,} bytes")
    if s["changed"]:
        print(f"  {_color('CHANGED', _C['YELLOW'])} ({len(s['changed'])})")
        fmt = "    {:<24}  {:>10}  ->  {:>10}  ({})"
        for c in s["changed"]:
            delta = f"{c['size_delta']:+,} bytes"
            dc    = _C['RED'] if c["size_delta"] > 0 else _C['GREEN']
            print(fmt.format(c["name"], f"{c['size_a']:,}", f"{c['size_b']:,}", _color(delta, dc)))
    if not s["added"] and not s["removed"] and not s["changed"]:
        print(f"  {_color('No section changes', _C['DIM'])}")

    # Imports
    imp = diff["imports"]
    _header(f"Imports  (A: {imp['count_a']}  ->  B: {imp['count_b']})")
    if imp["added"]:
        print(f"  {_color('ADDED', _C['GREEN'])} ({len(imp['added'])})")
        for name in imp["added"]:
            print(f"    {_color('+', _C['GREEN'])} {name}")
    if imp["removed"]:
        print(f"  {_color('REMOVED', _C['RED'])} ({len(imp['removed'])})")
        for name in imp["removed"]:
            print(f"    {_color('-', _C['RED'])} {name}")
    if not imp["added"] and not imp["removed"]:
        print(f"  {_color('No import changes', _C['DIM'])}")

    # Entropy
    ent = diff["entropy"]
    _header("Entropy")
    whole_delta_color = _C['RED'] if ent["whole_delta"] > 0.1 else (_C['GREEN'] if ent["whole_delta"] < -0.1 else _C['DIM'])
    _kv("Whole binary A ", f"{ent['whole_a']:.6f}")
    whole_delta_str = f"{ent['whole_delta']:+.6f}"
    _kv("Whole binary B ", f"{ent['whole_b']:.6f}  ({_color(whole_delta_str, whole_delta_color)})")
    if ent["changes"]:
        print()
        fmt = "  {:<20}  {:>10}  ->  {:>10}  {}"
        print(_color(fmt.format("Section", "A", "B", "Delta"), _C['DIM']))
        print(_color("  " + "─" * 58, _C['DIM']))
        for c in ent["changes"]:
            dc   = _C['RED'] if c["delta"] > 0 else _C['GREEN']
            warn = _color(" WARN", _C['YELLOW']) if c["b"] >= 7.0 else ""
            print(fmt.format(c["section"], f"{c['a']:.4f}", f"{c['b']:.4f}", _color(f"{c['delta']:+.4f}", dc) + warn))
    else:
        print(f"  {_color('No significant entropy changes', _C['DIM'])}")

    # Strings
    st = diff["strings"]
    _header(f"Strings  (A: {st['count_a']}  ->  B: {st['count_b']})")
    if st["added"]:
        print(f"  {_color('ADDED', _C['GREEN'])} ({len(st['added'])})")
        for sv in st["added"][:strings_limit]:
            print(f"    {_color('+', _C['GREEN'])} {sv}")
        if len(st["added"]) > strings_limit:
            print(_color(f"    ... {len(st['added']) - strings_limit} more", _C['DIM']))
    if st["removed"]:
        print(f"  {_color('REMOVED', _C['RED'])} ({len(st['removed'])})")
        for sv in st["removed"][:strings_limit]:
            print(f"    {_color('-', _C['RED'])} {sv}")
        if len(st["removed"]) > strings_limit:
            print(_color(f"    ... {len(st['removed']) - strings_limit} more", _C['DIM']))
    if not st["added"] and not st["removed"]:
        print(f"  {_color('No string changes', _C['DIM'])}")

    print()


# ------------------------------------------------------------------ #
#  HTML diff report                                                    #
# ------------------------------------------------------------------ #

def generate_html_report(a: ELFAnalyzer, b: ELFAnalyzer, diff: dict) -> str:
    """Generate a self-contained dark-theme HTML diff report."""

    def badge(val, t="YES", f="NO"):
        if val:
            return f'<span class="badge green">{t}</span>'
        return f'<span class="badge red">{f}</span>'

    def relro_badge(val):
        c = {"full": "green", "partial": "yellow", "none": "red"}.get(val, "red")
        return f'<span class="badge {c}">{val.upper()}</span>'

    def sec_row(label, key, a_sec, b_sec):
        av, bv = a_sec.get(key, False), b_sec.get(key, False)
        cls = ' class="changed-row"' if av != bv else ""
        return f'<tr{cls}><td>{label}</td><td>{badge(av)}</td><td>{badge(bv)}</td></tr>'

    def esc(s):
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    pa, pb = Path(a.path).name, Path(b.path).name
    h, fs, s, imp, ent, st = (diff["hashes"], diff["file_size"], diff["sections"],
                               diff["imports"], diff["entropy"], diff["strings"])

    # Section rows
    sec_rows = ""
    for sec in s["added"]:
        sec_rows += f'<tr class="added-row"><td>+</td><td>{sec["name"]}</td><td>{sec["type"]}</td><td>—</td><td>{sec["size"]:,}</td><td>—</td></tr>'
    for sec in s["removed"]:
        sec_rows += f'<tr class="removed-row"><td>−</td><td>{sec["name"]}</td><td>{sec["type"]}</td><td>{sec["size"]:,}</td><td>—</td><td>—</td></tr>'
    for c in s["changed"]:
        arrow = "▲" if c["size_delta"] > 0 else "▼"
        dc    = "added" if c["size_delta"] > 0 else "removed"
        sec_rows += f'<tr class="changed-row"><td>~</td><td>{c["name"]}</td><td>—</td><td>{c["size_a"]:,}</td><td>{c["size_b"]:,}</td><td><span class="{dc}">{arrow} {abs(c["size_delta"]):,}</span></td></tr>'
    if not sec_rows:
        sec_rows = '<tr><td colspan="6" class="dim">No section changes</td></tr>'

    # Import rows
    imp_rows = ""
    for name in imp["added"]:
        imp_rows += f'<tr class="added-row"><td>+</td><td>{name}</td></tr>'
    for name in imp["removed"]:
        imp_rows += f'<tr class="removed-row"><td>−</td><td>{name}</td></tr>'
    if not imp_rows:
        imp_rows = '<tr><td colspan="2" class="dim">No import changes</td></tr>'

    # Entropy rows
    ent_rows = ""
    for c in ent["changes"]:
        dc   = "added" if c["delta"] > 0 else "removed"
        warn = " ⚠" if c["b"] >= 7.0 else ""
        ent_rows += f'<tr class="changed-row"><td>{c["section"]}</td><td>{c["a"]:.4f}</td><td>{c["b"]:.4f}{warn}</td><td><span class="{dc}">{c["delta"]:+.4f}</span></td></tr>'
    if not ent_rows:
        ent_rows = '<tr><td colspan="4" class="dim">No significant entropy changes</td></tr>'

    # String rows (collapsible, capped at 300)
    def str_table_rows(items, cls, sym):
        rows = "".join(f'<tr class="{cls}"><td>{sym}</td><td><code>{esc(sv)}</code></td></tr>' for sv in items[:300])
        if len(items) > 300:
            rows += '<tr><td colspan="2" class="dim">… truncated to 300</td></tr>'
        return rows

    # Security comparison
    a_sec = a.security
    b_sec = b.security
    relro_changed = a_sec.get("relro") != b_sec.get("relro")
    relro_cls = ' class="changed-row"' if relro_changed else ""
    sec_compare = (
        sec_row("NX",           "nx",       a_sec, b_sec) +
        sec_row("PIE",          "pie",      a_sec, b_sec) +
        sec_row("Stack Canary", "canary",   a_sec, b_sec) +
        sec_row("FORTIFY",      "fortify",  a_sec, b_sec) +
        sec_row("Debug Syms",   "debug",    a_sec, b_sec) +
        sec_row("Stripped",     "stripped", a_sec, b_sec) +
        f'<tr{relro_cls}><td>RELRO</td><td>{relro_badge(a_sec.get("relro","none"))}</td><td>{relro_badge(b_sec.get("relro","none"))}</td></tr>'
    )

    hash_badge  = '<span class="badge green">IDENTICAL</span>' if h["identical"] else '<span class="badge red">DIFFERENT</span>'
    fs_dc       = "added" if fs["delta"] > 0 else ("removed" if fs["delta"] < 0 else "")
    ent_dc      = "added" if ent["whole_delta"] > 0.05 else ("removed" if ent["whole_delta"] < -0.05 else "")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>StaticElf Diff — {pa} vs {pb}</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;600;700&family=Syne:wght@400;600;800&display=swap');
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
:root{{
  --bg:#0b0d0f;--bg2:#111417;--bg3:#181c20;--border:#242830;
  --text:#c8d0db;--dim:#556070;--accent:#00e5c0;--accent2:#0099ff;
  --added:#00c875;--removed:#ff4a6e;--changed:#ffc44d;--heading:#eef2f7;
}}
html{{font-size:14px}}
body{{background:var(--bg);color:var(--text);font-family:'JetBrains Mono',monospace;line-height:1.6;min-height:100vh}}
.site-header{{
  background:linear-gradient(135deg,#0b0d0f 0%,#111820 50%,#0b0d12 100%);
  border-bottom:1px solid var(--border);padding:2.5rem 3rem 2rem;position:relative;overflow:hidden;
}}
.site-header::before{{content:'';position:absolute;top:-60px;left:-60px;width:300px;height:300px;
  background:radial-gradient(circle,rgba(0,229,192,.06) 0%,transparent 70%);pointer-events:none}}
.site-header::after{{content:'';position:absolute;bottom:-80px;right:5%;width:400px;height:400px;
  background:radial-gradient(circle,rgba(0,153,255,.05) 0%,transparent 70%);pointer-events:none}}
.logo{{font-family:'Syne',sans-serif;font-weight:800;font-size:1.1rem;letter-spacing:.15em;
  text-transform:uppercase;color:var(--accent);margin-bottom:1.2rem}}
.logo span{{color:var(--dim)}}
.diff-title{{font-family:'Syne',sans-serif;font-weight:600;font-size:1.6rem;color:var(--heading);margin-bottom:1rem}}
.binary-pills{{display:flex;align-items:center;gap:.75rem;flex-wrap:wrap}}
.pill{{background:var(--bg3);border:1px solid var(--border);border-radius:4px;padding:.3rem .8rem;font-size:.85rem}}
.pill.a{{border-left:3px solid var(--accent2)}}
.pill.b{{border-left:3px solid var(--accent)}}
.pill-label{{color:var(--dim);font-size:.75rem;margin-right:.4rem}}
.vs{{color:var(--dim)}}
.main{{max-width:1100px;margin:0 auto;padding:2rem 3rem 4rem}}
.summary-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:1rem;margin-bottom:2.5rem}}
.card{{background:var(--bg2);border:1px solid var(--border);border-radius:6px;padding:1.2rem 1.4rem}}
.card-label{{font-size:.7rem;letter-spacing:.12em;text-transform:uppercase;color:var(--dim);margin-bottom:.5rem}}
.card-value{{font-family:'Syne',sans-serif;font-size:1.35rem;font-weight:600;color:var(--heading)}}
.card-sub{{font-size:.75rem;color:var(--dim);margin-top:.25rem}}
.section{{margin-bottom:2.5rem}}
.section-title{{
  font-family:'Syne',sans-serif;font-weight:600;font-size:.75rem;letter-spacing:.18em;
  text-transform:uppercase;color:var(--accent);margin-bottom:1rem;padding-bottom:.5rem;
  border-bottom:1px solid var(--border);display:flex;align-items:center;gap:.6rem
}}
.section-title .count{{color:var(--dim);font-size:.7rem;font-weight:400}}
table{{width:100%;border-collapse:collapse;font-size:.82rem}}
th{{text-align:left;padding:.5rem .75rem;color:var(--dim);font-weight:400;font-size:.72rem;
  letter-spacing:.08em;text-transform:uppercase;border-bottom:1px solid var(--border)}}
td{{padding:.45rem .75rem;border-bottom:1px solid rgba(36,40,48,.5);vertical-align:middle}}
tr:last-child td{{border-bottom:none}}
code{{font-family:'JetBrains Mono',monospace;font-size:.8rem;word-break:break-all}}
.added-row td:first-child{{color:var(--added);font-weight:700}}
.removed-row td:first-child{{color:var(--removed);font-weight:700}}
.changed-row{{background:rgba(255,196,77,.04)}}
.added{{color:var(--added)}}.removed{{color:var(--removed)}}.changed{{color:var(--changed)}}.dim{{color:var(--dim);font-style:italic}}
.badge{{display:inline-block;padding:.15rem .55rem;border-radius:3px;font-size:.7rem;font-weight:600;letter-spacing:.06em}}
.badge.green{{background:rgba(0,200,117,.15);color:var(--added);border:1px solid rgba(0,200,117,.3)}}
.badge.red{{background:rgba(255,74,110,.12);color:var(--removed);border:1px solid rgba(255,74,110,.25)}}
.badge.yellow{{background:rgba(255,196,77,.12);color:var(--changed);border:1px solid rgba(255,196,77,.25)}}
.hash-grid{{display:grid;grid-template-columns:1fr 1fr;gap:1rem}}
.hash-block{{background:var(--bg3);border:1px solid var(--border);border-radius:4px;padding:1rem 1.2rem}}
.hash-block.a{{border-top:2px solid var(--accent2)}}.hash-block.b{{border-top:2px solid var(--accent)}}
.hash-label{{font-size:.68rem;color:var(--dim);letter-spacing:.1em;text-transform:uppercase;margin-bottom:.6rem}}
.hash-value{{font-size:.78rem;color:var(--text);word-break:break-all;line-height:1.8}}
.hash-key{{color:var(--dim);margin-right:.5rem}}
details{{margin-bottom:.5rem}}
summary{{cursor:pointer;padding:.5rem .75rem;background:var(--bg3);border:1px solid var(--border);
  border-radius:4px;font-size:.8rem;user-select:none;list-style:none;display:flex;align-items:center;gap:.5rem}}
summary::-webkit-details-marker{{display:none}}
summary::before{{content:'▶';font-size:.6rem;color:var(--dim);transition:transform .2s}}
details[open] summary::before{{transform:rotate(90deg)}}
.str-table{{margin-top:.5rem;max-height:300px;overflow-y:auto}}
::-webkit-scrollbar{{width:6px;height:6px}}
::-webkit-scrollbar-track{{background:var(--bg)}}
::-webkit-scrollbar-thumb{{background:var(--border);border-radius:3px}}
footer{{text-align:center;padding:2rem;color:var(--dim);font-size:.72rem;
  border-top:1px solid var(--border);letter-spacing:.06em}}
</style>
</head>
<body>
<header class="site-header">
  <div class="logo">Static<span>Elf</span> &mdash; Diff Report</div>
  <div class="diff-title">Binary Comparison</div>
  <div class="binary-pills">
    <div class="pill a"><span class="pill-label">A</span>{a.path}</div>
    <div class="vs">&#8594;</div>
    <div class="pill b"><span class="pill-label">B</span>{b.path}</div>
  </div>
</header>
<main class="main">
  <div class="summary-grid">
    <div class="card"><div class="card-label">Hash Match</div><div class="card-value">{hash_badge}</div></div>
    <div class="card">
      <div class="card-label">File Size Delta</div>
      <div class="card-value"><span class="{fs_dc}">{fs['delta']:+,}</span></div>
      <div class="card-sub">{fs['a']:,} &rarr; {fs['b']:,} bytes</div>
    </div>
    <div class="card">
      <div class="card-label">Sections</div>
      <div class="card-value">{s['count_a']} &rarr; {s['count_b']}</div>
      <div class="card-sub"><span class="added">+{len(s['added'])}</span>&nbsp;<span class="removed">&#8722;{len(s['removed'])}</span>&nbsp;<span class="changed">~{len(s['changed'])}</span></div>
    </div>
    <div class="card">
      <div class="card-label">Imports</div>
      <div class="card-value">{imp['count_a']} &rarr; {imp['count_b']}</div>
      <div class="card-sub"><span class="added">+{len(imp['added'])}</span>&nbsp;<span class="removed">&#8722;{len(imp['removed'])}</span></div>
    </div>
    <div class="card">
      <div class="card-label">Entropy (whole)</div>
      <div class="card-value"><span class="{ent_dc}">{ent['whole_delta']:+.4f}</span></div>
      <div class="card-sub">{ent['whole_a']:.4f} &rarr; {ent['whole_b']:.4f}</div>
    </div>
    <div class="card">
      <div class="card-label">Strings</div>
      <div class="card-value">{st['count_a']} &rarr; {st['count_b']}</div>
      <div class="card-sub"><span class="added">+{len(st['added'])}</span>&nbsp;<span class="removed">&#8722;{len(st['removed'])}</span></div>
    </div>
  </div>

  <div class="section">
    <div class="section-title">Hashes</div>
    <div class="hash-grid">
      <div class="hash-block a">
        <div class="hash-label">A &mdash; {pa}</div>
        <div class="hash-value"><span class="hash-key">MD5</span>{h['a'].get('md5','?')}<br><span class="hash-key">SHA256</span>{h['a'].get('sha256','?')}</div>
      </div>
      <div class="hash-block b">
        <div class="hash-label">B &mdash; {pb}</div>
        <div class="hash-value"><span class="hash-key">MD5</span>{h['b'].get('md5','?')}<br><span class="hash-key">SHA256</span>{h['b'].get('sha256','?')}</div>
      </div>
    </div>
  </div>

  <div class="section">
    <div class="section-title">Security Features</div>
    <table><thead><tr><th>Feature</th><th>A &mdash; {pa}</th><th>B &mdash; {pb}</th></tr></thead>
    <tbody>{sec_compare}</tbody></table>
  </div>

  <div class="section">
    <div class="section-title">Sections <span class="count">{s['count_a']} &rarr; {s['count_b']}</span></div>
    <table><thead><tr><th></th><th>Name</th><th>Type</th><th>Size A</th><th>Size B</th><th>Delta</th></tr></thead>
    <tbody>{sec_rows}</tbody></table>
  </div>

  <div class="section">
    <div class="section-title">Imports <span class="count">{imp['count_a']} &rarr; {imp['count_b']}</span></div>
    <table><thead><tr><th></th><th>Symbol</th></tr></thead>
    <tbody>{imp_rows}</tbody></table>
  </div>

  <div class="section">
    <div class="section-title">Entropy</div>
    <table><thead><tr><th>Section</th><th>A</th><th>B</th><th>Delta</th></tr></thead>
    <tbody>{ent_rows}</tbody></table>
  </div>

  <div class="section">
    <div class="section-title">Strings <span class="count">{st['count_a']} &rarr; {st['count_b']}</span></div>
    <details {'open' if len(st['added']) <= 50 else ''}>
      <summary><span class="added">+ {len(st['added'])} added</span></summary>
      <div class="str-table"><table><tbody>{str_table_rows(st['added'],'added-row','+')}</tbody></table></div>
    </details>
    <details {'open' if len(st['removed']) <= 50 else ''}>
      <summary><span class="removed">&#8722; {len(st['removed'])} removed</span></summary>
      <div class="str-table"><table><tbody>{str_table_rows(st['removed'],'removed-row','&#8722;')}</tbody></table></div>
    </details>
  </div>
</main>
<footer>Generated by StaticElf &mdash; {pa} vs {pb} &nbsp;|&nbsp; Produced by Wolfpack Cybernetics</footer>
</body></html>"""



# ------------------------------------------------------------------ #
#  Cross-architecture diff engine                                      #
# ------------------------------------------------------------------ #

# Signal weights (must sum to 1.0)
_XDIFF_WEIGHTS = {
    "strings":   0.25,
    "imports":   0.20,
    "symbols":   0.15,
    "entropy":   0.10,
    "functions": 0.07,
    "sections":  0.05,
    "asm":       0.18,   # WL graph kernel — highest structural signal
}

_CONFIDENCE_THRESHOLDS = [
    (0.75, "HIGH"),
    (0.45, "MEDIUM"),
    (0.00, "LOW"),
]


def _cosine(set_a: set, set_b: set) -> float:
    """
    Cosine similarity between two sets treated as binary term vectors.
    Equivalent to |A ∩ B| / sqrt(|A| * |B|).
    Returns 0.0 if either set is empty.
    """
    if not set_a or not set_b:
        return 0.0
    intersection = len(set_a & set_b)
    return intersection / math.sqrt(len(set_a) * len(set_b))


def _ratio(a: float, b: float) -> float:
    """Safe min/max ratio. Returns 1.0 if both are zero."""
    if a == 0 and b == 0:
        return 1.0
    if max(a, b) == 0:
        return 0.0
    return min(a, b) / max(a, b)


def _entropy_vector_cosine(ent_a: dict, ent_b: dict) -> float:
    """
    Cosine similarity between two entropy profiles across shared key sections.
    Uses the numeric entropy values as the vector components.
    """
    key_sections = [".text", ".data", ".rodata", ".bss", ".plt", ".got", "_whole_binary"]
    shared = [k for k in key_sections if k in ent_a and k in ent_b]
    if not shared:
        return 0.0
    va = [ent_a[k] for k in shared]
    vb = [ent_b[k] for k in shared]
    dot     = sum(x * y for x, y in zip(va, vb))
    mag_a   = math.sqrt(sum(x * x for x in va))
    mag_b   = math.sqrt(sum(x * x for x in vb))
    if mag_a == 0 or mag_b == 0:
        return 0.0
    return round(dot / (mag_a * mag_b), 6)


def _section_layout_score(secs_a: list, secs_b: list) -> float:
    """
    Combined section layout similarity:
      - 60%: Jaccard on section name sets
      - 40%: count ratio
    """
    names_a = {s["name"] for s in secs_a if s["name"]}
    names_b = {s["name"] for s in secs_b if s["name"]}
    union = names_a | names_b
    jaccard = len(names_a & names_b) / len(union) if union else 1.0
    count_sim = _ratio(len(secs_a), len(secs_b))
    return round(0.6 * jaccard + 0.4 * count_sim, 6)


def compute_xdiff(a: ELFAnalyzer, b: ELFAnalyzer) -> dict:
    """
    Compute a cross-architecture similarity analysis between two ELF binaries.

    Unlike compute_diff (which diffs same-arch binaries byte-by-byte), xdiff
    compares structural and semantic signals that survive recompilation across
    different CPU architectures from the same source code.

    Signals and weights:
        strings   30% — cosine similarity of printable string sets
        imports   25% — cosine similarity of imported function name sets
        symbols   20% — cosine similarity of all named symbol sets
        entropy   12% — cosine similarity of per-section entropy vectors
        functions  8% — ratio of STT_FUNC symbol counts
        sections   5% — section name Jaccard + count ratio

    Returns:
        dict with keys:
            score       (float)  — weighted similarity 0.0–1.0
            confidence  (str)    — LOW / MEDIUM / HIGH
            signals     (dict)   — per-signal scores and supporting data
            arch        (dict)   — architecture info for both binaries
    """
    # ── per-signal scores ─────────────────────────────────────────── #

    # Strings
    strs_a = set(a.strings)
    strs_b = set(b.strings)
    str_score    = _cosine(strs_a, strs_b)
    str_shared   = sorted(strs_a & strs_b)
    str_only_a   = sorted(strs_a - strs_b)
    str_only_b   = sorted(strs_b - strs_a)

    # Imports
    imps_a = {i["name"] for i in a.imports}
    imps_b = {i["name"] for i in b.imports}
    imp_score   = _cosine(imps_a, imps_b)
    imp_shared  = sorted(imps_a & imps_b)
    imp_only_a  = sorted(imps_a - imps_b)
    imp_only_b  = sorted(imps_b - imps_a)

    # Symbols
    syms_a = {s["name"] for s in a.symbols}
    syms_b = {s["name"] for s in b.symbols}
    sym_score   = _cosine(syms_a, syms_b)
    sym_shared  = sorted(syms_a & syms_b)
    sym_only_a  = sorted(syms_a - syms_b)
    sym_only_b  = sorted(syms_b - syms_a)

    # Entropy profile
    ent_score = _entropy_vector_cosine(a.entropy, b.entropy)
    key_secs  = [".text", ".data", ".rodata", ".bss", ".plt", ".got"]
    ent_table = []
    for k in key_secs:
        va = a.entropy.get(k)
        vb = b.entropy.get(k)
        if va is not None or vb is not None:
            ent_table.append({
                "section": k,
                "a":       round(va, 4) if va is not None else None,
                "b":       round(vb, 4) if vb is not None else None,
            })

    # Function count (STT_FUNC symbols)
    funcs_a    = sum(1 for s in a.symbols if s["type"] == "STT_FUNC")
    funcs_b    = sum(1 for s in b.symbols if s["type"] == "STT_FUNC")
    func_score = _ratio(funcs_a, funcs_b)

    # Section layout
    sec_score = _section_layout_score(a.sections, b.sections)

    # ── ASM / WL kernel ──────────────────────────────────────────── #
    asm_score = 0.0
    asm_note  = "capstone not available"
    if (_CAPSTONE and hasattr(a, "_asm_analyzer") and hasattr(b, "_asm_analyzer")
            and a._asm_analyzer and b._asm_analyzer):
        asm_score = a._asm_analyzer.wl_similarity(b._asm_analyzer)
        asm_note  = (f"WL kernel: {len(a._asm_analyzer.cfgs)} vs "
                     f"{len(b._asm_analyzer.cfgs)} functions")
    elif a.asm.get("available") and b.asm.get("available"):
        # Recompute from stored histograms if _asm_analyzer not present
        wl       = WLKernel()
        asm_score = wl.similarity(
            a.asm.get("wl_histogram", {}),
            b.asm.get("wl_histogram", {}),
        )
        asm_note = "WL kernel from stored histograms"

    # ── weighted final score ──────────────────────────────────────── #
    raw_scores = {
        "strings":   str_score,
        "imports":   imp_score,
        "symbols":   sym_score,
        "entropy":   ent_score,
        "functions": func_score,
        "sections":  sec_score,
        "asm":       asm_score,
    }
    final_score = round(
        sum(raw_scores[k] * w for k, w in _XDIFF_WEIGHTS.items()), 4
    )

    confidence = next(
        label for threshold, label in _CONFIDENCE_THRESHOLDS
        if final_score >= threshold
    )

    return {
        "score":      final_score,
        "confidence": confidence,
        "arch": {
            "a": a.arch,
            "b": b.arch,
        },
        "signals": {
            "strings": {
                "score":    round(str_score, 4),
                "weight":   _XDIFF_WEIGHTS["strings"],
                "count_a":  len(strs_a),
                "count_b":  len(strs_b),
                "shared":   str_shared,
                "only_a":   str_only_a,
                "only_b":   str_only_b,
            },
            "imports": {
                "score":    round(imp_score, 4),
                "weight":   _XDIFF_WEIGHTS["imports"],
                "count_a":  len(imps_a),
                "count_b":  len(imps_b),
                "shared":   imp_shared,
                "only_a":   imp_only_a,
                "only_b":   imp_only_b,
            },
            "symbols": {
                "score":    round(sym_score, 4),
                "weight":   _XDIFF_WEIGHTS["symbols"],
                "count_a":  len(syms_a),
                "count_b":  len(syms_b),
                "shared":   sym_shared,
                "only_a":   sym_only_a,
                "only_b":   sym_only_b,
            },
            "entropy": {
                "score":    round(ent_score, 4),
                "weight":   _XDIFF_WEIGHTS["entropy"],
                "table":    ent_table,
            },
            "functions": {
                "score":    round(func_score, 4),
                "weight":   _XDIFF_WEIGHTS["functions"],
                "count_a":  funcs_a,
                "count_b":  funcs_b,
            },
            "sections": {
                "score":    round(sec_score, 4),
                "weight":   _XDIFF_WEIGHTS["sections"],
                "count_a":  len(a.sections),
                "count_b":  len(b.sections),
                "shared":   sorted({s["name"] for s in a.sections if s["name"]}
                                   & {s["name"] for s in b.sections if s["name"]}),
            },
            "asm": {
                "score":         round(asm_score, 4),
                "weight":        _XDIFF_WEIGHTS["asm"],
                "note":          asm_note,
                "func_count_a":  a.asm.get("function_count",     0),
                "func_count_b":  b.asm.get("function_count",     0),
                "total_instr_a": a.asm.get("total_instructions", 0),
                "total_instr_b": b.asm.get("total_instructions", 0),
            },
        },
    }


# ------------------------------------------------------------------ #
#  Cross-diff terminal output                                          #
# ------------------------------------------------------------------ #

def print_xdiff(a: ELFAnalyzer, b: ELFAnalyzer, xd: dict, strings_limit: int = 20):
    pa, pb  = Path(a.path).name, Path(b.path).name
    score   = xd["score"]
    conf    = xd["confidence"]
    sig     = xd["signals"]

    score_color = (_C['GREEN'] if score >= 0.75
                   else _C['YELLOW'] if score >= 0.45
                   else _C['RED'])
    conf_color  = (_C['GREEN'] if conf == "HIGH"
                   else _C['YELLOW'] if conf == "MEDIUM"
                   else _C['RED'])

    arch_a = xd["arch"]["a"]
    arch_b = xd["arch"]["b"]

    print(f"\n{_color('◆ StaticElf XDiff', _C['BOLD'])}  {_color('Cross-Architecture Similarity', _C['DIM'])}")
    print(f"  {_color('A:', _C['DIM'])} {_color(a.path, _C['CYAN'])}  [{_color(arch_a.get('machine','?'), _C['YELLOW'])} {arch_a.get('bits','?')}-bit]")
    print(f"  {_color('B:', _C['DIM'])} {_color(b.path, _C['CYAN'])}  [{_color(arch_b.get('machine','?'), _C['YELLOW'])} {arch_b.get('bits','?')}-bit]")

    _header("Overall Similarity")
    print(f"  Score:      {_color(f'{score:.4f}', score_color)}  /  1.0000")
    print(f"  Confidence: {_color(conf, conf_color)}")
    print()

    # Signal breakdown table
    fmt = "  {:<14}  {:>6}  {:>6}  {:>10}  {}"
    print(_color(fmt.format("Signal", "Weight", "Score", "Weighted", ""), _C['DIM']))
    print(_color("  " + "─" * 56, _C['DIM']))
    for sig_name, weight in _XDIFF_WEIGHTS.items():
        s      = sig[sig_name]["score"]
        w      = weight
        wt     = round(s * w, 4)
        bar    = "█" * int(s * 10)
        sc     = _C['GREEN'] if s >= 0.75 else (_C['YELLOW'] if s >= 0.45 else _C['RED'])
        print(fmt.format(sig_name, f"{w:.0%}", _color(f"{s:.4f}", sc), f"{wt:.4f}", _color(bar, _C['CYAN'])))

    # ── Strings ───────────────────────────────────────────────────── #
    ss = sig["strings"]
    _header(f"Strings  (shared: {len(ss['shared'])}  |  A-only: {len(ss['only_a'])}  |  B-only: {len(ss['only_b'])})")
    if ss["shared"]:
        print(f"  {_color('SHARED', _C['GREEN'])} ({len(ss['shared'])})")
        for sv in ss["shared"][:strings_limit]:
            print(f"    {_color('=', _C['GREEN'])} {sv}")
        if len(ss["shared"]) > strings_limit:
            print(_color(f"    ... {len(ss['shared']) - strings_limit} more", _C['DIM']))
    if ss["only_a"]:
        print(f"  {_color(f'ONLY IN A [{pa}]', _C['YELLOW'])} ({len(ss['only_a'])})")
        for sv in ss["only_a"][:strings_limit]:
            print(f"    {_color('A', _C['YELLOW'])} {sv}")
        if len(ss["only_a"]) > strings_limit:
            print(_color(f"    ... {len(ss['only_a']) - strings_limit} more", _C['DIM']))
    if ss["only_b"]:
        print(f"  {_color(f'ONLY IN B [{pb}]', _C['YELLOW'])} ({len(ss['only_b'])})")
        for sv in ss["only_b"][:strings_limit]:
            print(f"    {_color('B', _C['YELLOW'])} {sv}")
        if len(ss["only_b"]) > strings_limit:
            print(_color(f"    ... {len(ss['only_b']) - strings_limit} more", _C['DIM']))

    # ── Imports ───────────────────────────────────────────────────── #
    si = sig["imports"]
    _header(f"Imports  (shared: {len(si['shared'])}  |  A-only: {len(si['only_a'])}  |  B-only: {len(si['only_b'])})")
    if si["shared"]:
        print(f"  {_color('SHARED', _C['GREEN'])} ({len(si['shared'])})")
        for n in si["shared"]:
            print(f"    {_color('=', _C['GREEN'])} {n}")
    if si["only_a"]:
        print(f"  {_color(f'ONLY IN A [{pa}]', _C['YELLOW'])} ({len(si['only_a'])})")
        for n in si["only_a"]:
            print(f"    {_color('A', _C['YELLOW'])} {n}")
    if si["only_b"]:
        print(f"  {_color(f'ONLY IN B [{pb}]', _C['YELLOW'])} ({len(si['only_b'])})")
        for n in si["only_b"]:
            print(f"    {_color('B', _C['YELLOW'])} {n}")

    # ── Symbols ───────────────────────────────────────────────────── #
    sy = sig["symbols"]
    _header(f"Symbols  (shared: {len(sy['shared'])}  |  A-only: {len(sy['only_a'])}  |  B-only: {len(sy['only_b'])})")
    if sy["shared"]:
        print(f"  {_color('SHARED', _C['GREEN'])} ({len(sy['shared'])})")
        for n in sy["shared"][:strings_limit]:
            print(f"    {_color('=', _C['GREEN'])} {n}")
        if len(sy["shared"]) > strings_limit:
            print(_color(f"    ... {len(sy['shared']) - strings_limit} more", _C['DIM']))

    # ── Entropy ───────────────────────────────────────────────────── #
    se = sig["entropy"]
    _header(f"Entropy Profile  (cosine similarity: {se['score']:.4f})")
    fmt = "  {:<14}  {:>10}  {:>10}  {}"
    print(_color(fmt.format("Section", "A", "B", ""), _C['DIM']))
    print(_color("  " + "─" * 44, _C['DIM']))
    for row in se["table"]:
        va   = f"{row['a']:.4f}" if row["a"] is not None else "—"
        vb   = f"{row['b']:.4f}" if row["b"] is not None else "—"
        diff = abs((row["a"] or 0.0) - (row["b"] or 0.0))
        dc   = _C['RED'] if diff > 0.5 else (_C['YELLOW'] if diff > 0.2 else _C['GREEN'])
        bar  = _color("▐" * int(diff * 10), dc)
        print(fmt.format(row["section"], va, vb, bar))

    # ── Functions ─────────────────────────────────────────────────── #
    sf = sig["functions"]
    _header(f"Function Count  (A: {sf['count_a']}  |  B: {sf['count_b']}  |  ratio: {sf['score']:.4f})")

    # ── Sections ──────────────────────────────────────────────────── #
    sc = sig["sections"]
    _header(f"Section Layout  (A: {sc['count_a']}  |  B: {sc['count_b']}  |  shared names: {len(sc['shared'])})")
    if sc["shared"]:
        for n in sc["shared"]:
            print(f"    {_color('=', _C['GREEN'])} {n}")

    print()


# ------------------------------------------------------------------ #
#  Cross-diff HTML report                                              #
# ------------------------------------------------------------------ #

def generate_xdiff_html(a: ELFAnalyzer, b: ELFAnalyzer, xd: dict) -> str:
    """Generate a self-contained dark-theme HTML cross-arch similarity report."""

    def esc(s):
        return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    pa, pb    = Path(a.path).name, Path(b.path).name
    score     = xd["score"]
    conf      = xd["confidence"]
    sig       = xd["signals"]
    arch_a    = xd["arch"]["a"]
    arch_b    = xd["arch"]["b"]

    score_pct = int(score * 100)
    conf_cls  = {"HIGH": "green", "MEDIUM": "yellow", "LOW": "red"}.get(conf, "red")
    score_cls = "green" if score >= 0.75 else ("yellow" if score >= 0.45 else "red")

    def sig_bar(s):
        pct = int(s * 100)
        cls = "green" if s >= 0.75 else ("yellow" if s >= 0.45 else "red")
        return f'<div class="sig-bar"><div class="sig-fill {cls}" style="width:{pct}%"></div></div>'

    def str_rows(items, cls, sym, limit=200):
        rows = "".join(f'<tr class="{cls}"><td>{sym}</td><td><code>{esc(v)}</code></td></tr>'
                       for v in items[:limit])
        if len(items) > limit:
            rows += f'<tr><td colspan="2" class="dim">… truncated to {limit}</td></tr>'
        return rows

    # Signal rows for summary table
    signal_rows = ""
    for sig_name, weight in _XDIFF_WEIGHTS.items():
        s      = sig[sig_name]["score"]
        wt     = round(s * weight, 4)
        sc     = "green" if s >= 0.75 else ("yellow" if s >= 0.45 else "red")
        signal_rows += f"""
        <tr>
          <td>{sig_name}</td>
          <td>{weight:.0%}</td>
          <td><span class="badge {sc}">{s:.4f}</span></td>
          <td>{sig_bar(s)}</td>
          <td>{wt:.4f}</td>
        </tr>"""

    # Entropy table rows
    ent_rows = ""
    for row in sig["entropy"]["table"]:
        va   = f"{row['a']:.4f}" if row["a"] is not None else "—"
        vb   = f"{row['b']:.4f}" if row["b"] is not None else "—"
        diff = abs((row["a"] or 0.0) - (row["b"] or 0.0))
        dc   = "red" if diff > 0.5 else ("yellow" if diff > 0.2 else "green")
        ent_rows += f'<tr><td>{row["section"]}</td><td>{va}</td><td>{vb}</td><td><span class="badge {dc}">{diff:.4f}</span></td></tr>'

    ss, si, sy, sf, sc = (sig["strings"], sig["imports"], sig["symbols"],
                          sig["functions"], sig["sections"])

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>StaticElf XDiff — {pa} vs {pb}</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;600;700&family=Syne:wght@400;600;800&display=swap');
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
:root{{
  --bg:#090c10;--bg2:#0f1318;--bg3:#161b22;--border:#1e2530;
  --text:#b8c4d0;--dim:#4a5568;--accent:#7c3aed;--accent2:#06b6d4;
  --added:#10b981;--removed:#f43f5e;--changed:#f59e0b;--heading:#e2e8f0;
}}
html{{font-size:14px}}
body{{background:var(--bg);color:var(--text);font-family:'JetBrains Mono',monospace;line-height:1.6}}
.site-header{{
  background:linear-gradient(135deg,#090c10 0%,#0f1624 60%,#09100c 100%);
  border-bottom:1px solid var(--border);padding:2.5rem 3rem 2rem;position:relative;overflow:hidden
}}
.site-header::before{{content:'';position:absolute;top:-80px;left:-40px;width:400px;height:400px;
  background:radial-gradient(circle,rgba(124,58,237,.07) 0%,transparent 70%);pointer-events:none}}
.site-header::after{{content:'';position:absolute;bottom:-100px;right:8%;width:500px;height:500px;
  background:radial-gradient(circle,rgba(6,182,212,.05) 0%,transparent 70%);pointer-events:none}}
.logo{{font-family:'Syne',sans-serif;font-weight:800;font-size:1.1rem;letter-spacing:.15em;
  text-transform:uppercase;color:var(--accent);margin-bottom:1rem}}
.logo span{{color:var(--dim)}}
.diff-title{{font-family:'Syne',sans-serif;font-weight:600;font-size:1.5rem;color:var(--heading);margin-bottom:.75rem}}
.arch-pills{{display:flex;align-items:center;gap:.75rem;flex-wrap:wrap}}
.pill{{background:var(--bg3);border:1px solid var(--border);border-radius:4px;padding:.3rem .8rem;font-size:.82rem}}
.pill.a{{border-left:3px solid var(--accent)}}.pill.b{{border-left:3px solid var(--accent2)}}
.pill-label{{color:var(--dim);font-size:.72rem;margin-right:.4rem}}
.arch-tag{{font-size:.72rem;color:var(--accent2);margin-left:.5rem;border:1px solid rgba(6,182,212,.3);
  border-radius:3px;padding:.1rem .4rem;background:rgba(6,182,212,.08)}}
.main{{max-width:1100px;margin:0 auto;padding:2rem 3rem 4rem}}

/* Score hero */
.score-hero{{display:flex;align-items:center;gap:2.5rem;background:var(--bg2);
  border:1px solid var(--border);border-radius:8px;padding:2rem 2.5rem;margin-bottom:2rem}}
.score-dial{{text-align:center;flex-shrink:0}}
.score-num{{font-family:'Syne',sans-serif;font-size:3.5rem;font-weight:800;line-height:1}}
.score-label{{font-size:.7rem;letter-spacing:.15em;text-transform:uppercase;color:var(--dim);margin-top:.3rem}}
.score-meta{{flex:1}}
.score-meta h2{{font-family:'Syne',sans-serif;font-size:1rem;font-weight:600;color:var(--heading);margin-bottom:.5rem}}
.conf-badge{{display:inline-block;padding:.25rem .75rem;border-radius:4px;font-size:.8rem;
  font-weight:700;letter-spacing:.1em;margin-bottom:.75rem}}
.arch-compare{{display:grid;grid-template-columns:1fr 1fr;gap:1rem;margin-top:.75rem}}
.arch-box{{background:var(--bg3);border:1px solid var(--border);border-radius:4px;padding:.75rem 1rem;font-size:.8rem}}
.arch-box.a{{border-top:2px solid var(--accent)}}.arch-box.b{{border-top:2px solid var(--accent2)}}
.arch-box-label{{color:var(--dim);font-size:.68rem;letter-spacing:.1em;text-transform:uppercase;margin-bottom:.4rem}}

/* Signal table */
.section{{margin-bottom:2rem}}
.section-title{{font-family:'Syne',sans-serif;font-weight:600;font-size:.72rem;letter-spacing:.18em;
  text-transform:uppercase;color:var(--accent);margin-bottom:.75rem;padding-bottom:.4rem;
  border-bottom:1px solid var(--border);display:flex;align-items:center;gap:.6rem}}
.section-title .count{{color:var(--dim);font-size:.68rem;font-weight:400}}
table{{width:100%;border-collapse:collapse;font-size:.82rem}}
th{{text-align:left;padding:.45rem .75rem;color:var(--dim);font-weight:400;font-size:.7rem;
  letter-spacing:.08em;text-transform:uppercase;border-bottom:1px solid var(--border)}}
td{{padding:.4rem .75rem;border-bottom:1px solid rgba(30,37,48,.6);vertical-align:middle}}
tr:last-child td{{border-bottom:none}}
code{{font-family:'JetBrains Mono',monospace;font-size:.78rem;word-break:break-all}}
.shared-row td:first-child{{color:var(--added);font-weight:700}}
.only-a-row td:first-child{{color:var(--changed);font-weight:700}}
.only-b-row td:first-child{{color:var(--accent2);font-weight:700}}
.dim{{color:var(--dim);font-style:italic}}
.badge{{display:inline-block;padding:.15rem .5rem;border-radius:3px;font-size:.7rem;font-weight:600;letter-spacing:.05em}}
.badge.green{{background:rgba(16,185,129,.15);color:var(--added);border:1px solid rgba(16,185,129,.3)}}
.badge.yellow{{background:rgba(245,158,11,.12);color:var(--changed);border:1px solid rgba(245,158,11,.25)}}
.badge.red{{background:rgba(244,63,94,.12);color:var(--removed);border:1px solid rgba(244,63,94,.25)}}
.badge.blue{{background:rgba(6,182,212,.12);color:var(--accent2);border:1px solid rgba(6,182,212,.25)}}
.sig-bar{{background:var(--bg3);border-radius:2px;height:6px;width:120px;overflow:hidden}}
.sig-fill{{height:100%;border-radius:2px}}
.sig-fill.green{{background:var(--added)}}.sig-fill.yellow{{background:var(--changed)}}.sig-fill.red{{background:var(--removed)}}
details{{margin-bottom:.5rem}}
summary{{cursor:pointer;padding:.45rem .75rem;background:var(--bg3);border:1px solid var(--border);
  border-radius:4px;font-size:.8rem;user-select:none;list-style:none;display:flex;align-items:center;gap:.5rem}}
summary::-webkit-details-marker{{display:none}}
summary::before{{content:'▶';font-size:.55rem;color:var(--dim);transition:transform .2s}}
details[open] summary::before{{transform:rotate(90deg)}}
.str-table{{margin-top:.4rem;max-height:280px;overflow-y:auto}}
::-webkit-scrollbar{{width:5px;height:5px}}
::-webkit-scrollbar-track{{background:var(--bg)}}
::-webkit-scrollbar-thumb{{background:var(--border);border-radius:3px}}
footer{{text-align:center;padding:2rem;color:var(--dim);font-size:.7rem;
  border-top:1px solid var(--border);letter-spacing:.06em}}
</style>
</head>
<body>
<header class="site-header">
  <div class="logo">Static<span>Elf</span> &mdash; XDiff</div>
  <div class="diff-title">Cross-Architecture Similarity</div>
  <div class="arch-pills">
    <div class="pill a">
      <span class="pill-label">A</span>{esc(a.path)}
      <span class="arch-tag">{esc(arch_a.get('machine','?'))} {arch_a.get('bits','?')}-bit</span>
    </div>
    <span style="color:var(--dim)">&#8644;</span>
    <div class="pill b">
      <span class="pill-label">B</span>{esc(b.path)}
      <span class="arch-tag">{esc(arch_b.get('machine','?'))} {arch_b.get('bits','?')}-bit</span>
    </div>
  </div>
</header>

<main class="main">

  <!-- Score hero -->
  <div class="score-hero">
    <div class="score-dial">
      <div class="score-num" style="color:var(--{'added' if score>=0.75 else 'changed' if score>=0.45 else 'removed'})">{score:.4f}</div>
      <div class="score-label">Similarity Score</div>
    </div>
    <div class="score-meta">
      <h2>Confidence: <span class="conf-badge badge {conf_cls}">{conf}</span></h2>
      <div class="arch-compare">
        <div class="arch-box a">
          <div class="arch-box-label">Binary A</div>
          <b>{esc(arch_a.get('machine','?'))}</b> {arch_a.get('bits','?')}-bit
          {arch_a.get('endianness','?')}-endian &mdash; {arch_a.get('elf_type','?')}
        </div>
        <div class="arch-box b">
          <div class="arch-box-label">Binary B</div>
          <b>{esc(arch_b.get('machine','?'))}</b> {arch_b.get('bits','?')}-bit
          {arch_b.get('endianness','?')}-endian &mdash; {arch_b.get('elf_type','?')}
        </div>
      </div>
    </div>
  </div>

  <!-- Signal breakdown -->
  <div class="section">
    <div class="section-title">Signal Breakdown</div>
    <table>
      <thead><tr><th>Signal</th><th>Weight</th><th>Score</th><th>Bar</th><th>Contribution</th></tr></thead>
      <tbody>{signal_rows}</tbody>
    </table>
  </div>

  <!-- Strings -->
  <div class="section">
    <div class="section-title">
      Strings
      <span class="count">shared {len(ss['shared'])} &nbsp;|&nbsp; A-only {len(ss['only_a'])} &nbsp;|&nbsp; B-only {len(ss['only_b'])}</span>
    </div>
    <details open>
      <summary><span style="color:var(--added)">= {len(ss['shared'])} shared</span></summary>
      <div class="str-table"><table><tbody>{str_rows(ss['shared'],'shared-row','=')}</tbody></table></div>
    </details>
    <details>
      <summary><span style="color:var(--changed)">A {len(ss['only_a'])} only in {pa}</span></summary>
      <div class="str-table"><table><tbody>{str_rows(ss['only_a'],'only-a-row','A')}</tbody></table></div>
    </details>
    <details>
      <summary><span style="color:var(--accent2)">B {len(ss['only_b'])} only in {pb}</span></summary>
      <div class="str-table"><table><tbody>{str_rows(ss['only_b'],'only-b-row','B')}</tbody></table></div>
    </details>
  </div>

  <!-- Imports -->
  <div class="section">
    <div class="section-title">
      Imports
      <span class="count">shared {len(si['shared'])} &nbsp;|&nbsp; A-only {len(si['only_a'])} &nbsp;|&nbsp; B-only {len(si['only_b'])}</span>
    </div>
    <details open>
      <summary><span style="color:var(--added)">= {len(si['shared'])} shared</span></summary>
      <div class="str-table"><table><tbody>{str_rows(si['shared'],'shared-row','=')}</tbody></table></div>
    </details>
    <details>
      <summary><span style="color:var(--changed)">A {len(si['only_a'])} only in {pa}</span></summary>
      <div class="str-table"><table><tbody>{str_rows(si['only_a'],'only-a-row','A')}</tbody></table></div>
    </details>
    <details>
      <summary><span style="color:var(--accent2)">B {len(si['only_b'])} only in {pb}</span></summary>
      <div class="str-table"><table><tbody>{str_rows(si['only_b'],'only-b-row','B')}</tbody></table></div>
    </details>
  </div>

  <!-- Symbols -->
  <div class="section">
    <div class="section-title">
      Symbols
      <span class="count">shared {len(sy['shared'])} &nbsp;|&nbsp; A-only {len(sy['only_a'])} &nbsp;|&nbsp; B-only {len(sy['only_b'])}</span>
    </div>
    <details open>
      <summary><span style="color:var(--added)">= {len(sy['shared'])} shared</span></summary>
      <div class="str-table"><table><tbody>{str_rows(sy['shared'],'shared-row','=')}</tbody></table></div>
    </details>
  </div>

  <!-- Entropy -->
  <div class="section">
    <div class="section-title">Entropy Profile <span class="count">cosine similarity {sig['entropy']['score']:.4f}</span></div>
    <table>
      <thead><tr><th>Section</th><th>A</th><th>B</th><th>|Delta|</th></tr></thead>
      <tbody>{ent_rows}</tbody>
    </table>
  </div>

  <!-- Functions + Sections -->
  <div class="section">
    <div class="section-title">Function Count &amp; Section Layout</div>
    <table>
      <thead><tr><th>Metric</th><th>A &mdash; {pa}</th><th>B &mdash; {pb}</th><th>Score</th></tr></thead>
      <tbody>
        <tr><td>Function count</td><td>{sf['count_a']}</td><td>{sf['count_b']}</td>
          <td><span class="badge {('green' if sf['score']>=0.75 else 'yellow' if sf['score']>=0.45 else 'red')}">{sf['score']:.4f}</span></td></tr>
        <tr><td>Section count</td><td>{sc['count_a']}</td><td>{sc['count_b']}</td>
          <td><span class="badge {('green' if sc['score']>=0.75 else 'yellow' if sc['score']>=0.45 else 'red')}">{sc['score']:.4f}</span></td></tr>
        <tr><td>Shared section names</td><td colspan="2">{", ".join(sc['shared']) or "—"}</td><td>—</td></tr>
      </tbody>
    </table>
  </div>

</main>
<footer>Generated by StaticElf XDiff &mdash; {pa} vs {pb} &nbsp;|&nbsp; Produced by Wolfpack Cybernetics</footer>
</body></html>"""


# ------------------------------------------------------------------ #
#  N×N cross-arch matrix engine                                        #
# ------------------------------------------------------------------ #

def compute_matrix(analyzers: list) -> dict:
    """
    Compute a full N×N pairwise xdiff similarity matrix.

    Every unique pair (i, j) where i < j is compared once using
    compute_xdiff(). Results are stored symmetrically.

    Args:
        analyzers: List of analyzed ELFAnalyzer instances (N >= 2)

    Returns:
        dict with keys:
            labels  (list[str])        — short filename labels
            paths   (list[str])        — full paths
            arches  (list[str])        — architecture strings per binary
            matrix  (list[list[float]])— N×N similarity scores
            pairs   (list[dict])       — all pair results sorted by score desc
    """
    n      = len(analyzers)
    labels = [Path(az.path).name for az in analyzers]
    paths  = [az.path for az in analyzers]
    arches = [f"{az.arch.get('machine','?')} {az.arch.get('bits','?')}-bit"
              for az in analyzers]

    # Init N×N matrix — diagonal is 1.0 (identical to self)
    matrix = [[1.0 if i == j else 0.0 for j in range(n)] for i in range(n)]
    pairs  = []

    for i in range(n):
        for j in range(i + 1, n):
            xd    = compute_xdiff(analyzers[i], analyzers[j])
            score = xd["score"]
            matrix[i][j] = score
            matrix[j][i] = score
            pairs.append({
                "i":          i,
                "j":          j,
                "label_a":    labels[i],
                "label_b":    labels[j],
                "arch_a":     arches[i],
                "arch_b":     arches[j],
                "score":      score,
                "confidence": xd["confidence"],
                "signals":    xd["signals"],
            })

    pairs.sort(key=lambda p: p["score"], reverse=True)

    return {
        "labels": labels,
        "paths":  paths,
        "arches": arches,
        "matrix": matrix,
        "pairs":  pairs,
    }


# ------------------------------------------------------------------ #
#  Matrix terminal output                                              #
# ------------------------------------------------------------------ #

def print_matrix(result: dict, strings_limit: int = 10):
    n      = len(result["labels"])
    labels = result["labels"]
    arches = result["arches"]
    matrix = result["matrix"]
    pairs  = result["pairs"]

    print(f"\n{_color('◆ StaticElf XDiff Matrix', _C['BOLD'])}  "
          f"{_color(f'{n}×{n} pairwise cross-arch comparison', _C['DIM'])}")
    print()

    # Print arch summary
    for i, (lbl, arch) in enumerate(zip(labels, arches)):
        print(f"  {_color(f'[{i}]', _C['CYAN'])} {lbl:<30} {_color(arch, _C['YELLOW'])}")
    print()

    # Similarity matrix table
    _header(f"Similarity Matrix  ({n}×{n})")
    col_w = 8
    # Header row
    header = "  " + " " * 28
    for i in range(n):
        header += f"  [{i}]".ljust(col_w)
    print(_color(header, _C['DIM']))
    print(_color("  " + "─" * (28 + n * col_w + 2), _C['DIM']))

    for i in range(n):
        row = f"  [{i}] {labels[i][:24]:<24}"
        for j in range(n):
            s = matrix[i][j]
            if i == j:
                cell = _color(f"{'—':>{col_w-2}}", _C['DIM'])
            else:
                sc   = (_C['GREEN'] if s >= 0.75
                        else _C['YELLOW'] if s >= 0.45
                        else _C['RED'])
                cell = _color(f"{s:.4f}".rjust(col_w - 1), sc)
            row += " " + cell
        print(row)

    # Ranked pairs
    _header("Ranked Pairs  (highest → lowest similarity)")
    fmt = "  {:>4}  {:<26} {:<26}  {:>7}  {:<8}  {}"
    print(_color(fmt.format("#", "Binary A", "Binary B", "Score", "Conf", "Top signal"), _C['DIM']))
    print(_color("  " + "─" * 86, _C['DIM']))

    for rank, pair in enumerate(pairs, 1):
        score = pair["score"]
        sc    = (_C['GREEN'] if score >= 0.75
                 else _C['YELLOW'] if score >= 0.45
                 else _C['RED'])
        cc    = (_C['GREEN'] if pair["confidence"] == "HIGH"
                 else _C['YELLOW'] if pair["confidence"] == "MEDIUM"
                 else _C['RED'])
        # Find highest scoring signal for quick read
        top_sig = max(pair["signals"].items(),
                      key=lambda kv: kv[1]["score"] * _XDIFF_WEIGHTS[kv[0]])
        top_str = f"{top_sig[0]}={top_sig[1]['score']:.3f}"
        print(fmt.format(
            rank,
            pair["label_a"][:25],
            pair["label_b"][:25],
            _color(f"{score:.4f}", sc),
            _color(pair["confidence"], cc),
            _color(top_str, _C['DIM']),
        ))

    # Per-signal breakdown
    _header("Per-Signal Breakdown")
    sig_fmt = "  {:<26} {:<26}  " + "  ".join(["{:>8}"] * 6)
    sig_names = list(_XDIFF_WEIGHTS.keys())
    print(_color(sig_fmt.format("Binary A", "Binary B", *sig_names), _C['DIM']))
    print(_color("  " + "─" * 100, _C['DIM']))

    for pair in pairs:
        scores = [pair["signals"][s]["score"] for s in sig_names]
        cells  = []
        for s in scores:
            sc = (_C['GREEN'] if s >= 0.75
                  else _C['YELLOW'] if s >= 0.45
                  else _C['RED'])
            cells.append(_color(f"{s:.4f}", sc))
        print(sig_fmt.format(pair["label_a"][:25], pair["label_b"][:25], *cells))

    print()


# ------------------------------------------------------------------ #
#  Matrix HTML report                                                  #
# ------------------------------------------------------------------ #

def generate_matrix_html(analyzers: list, result: dict) -> str:
    """Generate a self-contained dark-theme N×N matrix HTML report."""

    def esc(s):
        return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    n      = len(result["labels"])
    labels = result["labels"]
    arches = result["arches"]
    matrix = result["matrix"]
    pairs  = result["pairs"]

    def score_color_css(s):
        if s >= 0.75: return "#10b981"
        if s >= 0.45: return "#f59e0b"
        return "#f43f5e"

    def score_bg_css(s):
        if s >= 0.75: return "rgba(16,185,129,0.15)"
        if s >= 0.45: return "rgba(245,158,11,0.12)"
        return "rgba(244,63,94,0.10)"

    def badge(s, label=None):
        txt = label or f"{s:.4f}"
        cls = "green" if s >= 0.75 else ("yellow" if s >= 0.45 else "red")
        return f'<span class="badge {cls}">{txt}</span>'

    def conf_badge(c):
        cls = {"HIGH": "green", "MEDIUM": "yellow", "LOW": "red"}.get(c, "red")
        return f'<span class="badge {cls}">{c}</span>'

    # ── heatmap cells ─────────────────────────────────────────────── #
    heatmap_header = "<tr><th></th>" + "".join(
        f'<th title="{esc(labels[j])}">[{j}]</th>' for j in range(n)
    ) + "</tr>"

    heatmap_rows = ""
    for i in range(n):
        heatmap_rows += f'<tr><th>[{i}] {esc(labels[i][:20])}</th>'
        for j in range(n):
            if i == j:
                heatmap_rows += '<td class="diag">—</td>'
            else:
                s    = matrix[i][j]
                bg   = score_bg_css(s)
                col  = score_color_css(s)
                link = f"#pair-{min(i,j)}-{max(i,j)}"
                heatmap_rows += (
                    f'<td style="background:{bg};color:{col}" title="{esc(labels[i])} vs {esc(labels[j])}">'
                    f'<a href="{link}" style="color:inherit;text-decoration:none">{s:.3f}</a></td>'
                )
        heatmap_rows += "</tr>"

    # ── ranked pair rows ──────────────────────────────────────────── #
    ranked_rows = ""
    for rank, pair in enumerate(pairs, 1):
        sig_cells = "".join(
            f'<td>{badge(pair["signals"][s]["score"])}</td>'
            for s in _XDIFF_WEIGHTS
        )
        anchor = f'pair-{min(pair["i"], pair["j"])}-{max(pair["i"], pair["j"])}'
        ranked_rows += f"""
        <tr id="{anchor}">
          <td class="dim">{rank}</td>
          <td><code>{esc(pair['label_a'])}</code><br><span class="arch-tag">{esc(pair['arch_a'])}</span></td>
          <td><code>{esc(pair['label_b'])}</code><br><span class="arch-tag">{esc(pair['arch_b'])}</span></td>
          <td>{badge(pair['score'])}</td>
          <td>{conf_badge(pair['confidence'])}</td>
          {sig_cells}
        </tr>"""

    # ── legend rows for binary index ──────────────────────────────── #
    legend_rows = ""
    for i, az in enumerate(analyzers):
        arch = az.arch
        legend_rows += f"""
        <tr>
          <td class="dim">[{i}]</td>
          <td><code>{esc(labels[i])}</code></td>
          <td>{esc(arch.get('machine','?'))}</td>
          <td>{arch.get('bits','?')}-bit</td>
          <td>{arch.get('endianness','?')}</td>
          <td>{esc(arch.get('elf_type','?'))}</td>
          <td>{esc(arch.get('abi','?'))}</td>
        </tr>"""

    sig_header_cells = "".join(f"<th>{s}</th>" for s in _XDIFF_WEIGHTS)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>StaticElf XDiff Matrix — {n} binaries</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;600;700&family=Syne:wght@400;700;800&display=swap');
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
:root{{
  --bg:#07090c;--bg2:#0d1117;--bg3:#141920;--border:#1a2030;
  --text:#b0bec8;--dim:#3d4f60;--accent:#7c3aed;--accent2:#06b6d4;
  --added:#10b981;--removed:#f43f5e;--changed:#f59e0b;--heading:#dde4ec;
}}
html{{font-size:13px}}
body{{background:var(--bg);color:var(--text);font-family:'JetBrains Mono',monospace;line-height:1.6}}
a{{color:inherit}}
.site-header{{
  background:linear-gradient(135deg,#07090c 0%,#0d1420 55%,#07090c 100%);
  border-bottom:1px solid var(--border);padding:2rem 3rem 1.75rem;position:relative;overflow:hidden
}}
.site-header::before{{content:'';position:absolute;top:-60px;left:-30px;width:350px;height:350px;
  background:radial-gradient(circle,rgba(124,58,237,.07) 0%,transparent 70%);pointer-events:none}}
.logo{{font-family:'Syne',sans-serif;font-weight:800;font-size:1rem;letter-spacing:.15em;
  text-transform:uppercase;color:var(--accent);margin-bottom:.75rem}}
.logo span{{color:var(--dim)}}
.page-title{{font-family:'Syne',sans-serif;font-weight:700;font-size:1.4rem;color:var(--heading);margin-bottom:.5rem}}
.subtitle{{font-size:.8rem;color:var(--dim)}}
.main{{max-width:1300px;margin:0 auto;padding:2rem 3rem 4rem}}
.section{{margin-bottom:2.5rem}}
.section-title{{
  font-family:'Syne',sans-serif;font-weight:600;font-size:.72rem;letter-spacing:.18em;
  text-transform:uppercase;color:var(--accent);margin-bottom:.9rem;padding-bottom:.4rem;
  border-bottom:1px solid var(--border);display:flex;align-items:center;gap:.6rem
}}
.section-title .count{{color:var(--dim);font-size:.68rem;font-weight:400}}
/* heatmap */
.heatmap-wrap{{overflow-x:auto}}
.heatmap{{border-collapse:collapse;font-size:.78rem}}
.heatmap th{{padding:.4rem .6rem;color:var(--dim);font-weight:400;font-size:.7rem;
  border:1px solid var(--border);background:var(--bg2);white-space:nowrap}}
.heatmap td{{padding:.35rem .55rem;text-align:center;border:1px solid var(--border);
  font-weight:600;font-size:.78rem;white-space:nowrap;transition:filter .15s}}
.heatmap td:hover{{filter:brightness(1.3)}}
.heatmap td.diag{{color:var(--dim);background:var(--bg2)}}
/* tables */
table.data{{width:100%;border-collapse:collapse;font-size:.8rem}}
table.data th{{text-align:left;padding:.45rem .7rem;color:var(--dim);font-weight:400;
  font-size:.7rem;letter-spacing:.07em;text-transform:uppercase;border-bottom:1px solid var(--border)}}
table.data td{{padding:.4rem .7rem;border-bottom:1px solid rgba(26,32,48,.7);vertical-align:middle}}
table.data tr:last-child td{{border-bottom:none}}
table.data tr:target{{background:rgba(124,58,237,.08);outline:1px solid rgba(124,58,237,.3)}}
code{{font-family:'JetBrains Mono',monospace;font-size:.78rem}}
.dim{{color:var(--dim)}}
.badge{{display:inline-block;padding:.13rem .5rem;border-radius:3px;font-size:.68rem;font-weight:700;letter-spacing:.05em}}
.badge.green{{background:rgba(16,185,129,.15);color:#10b981;border:1px solid rgba(16,185,129,.3)}}
.badge.yellow{{background:rgba(245,158,11,.12);color:#f59e0b;border:1px solid rgba(245,158,11,.25)}}
.badge.red{{background:rgba(244,63,94,.12);color:#f43f5e;border:1px solid rgba(244,63,94,.25)}}
.arch-tag{{font-size:.68rem;color:var(--accent2);border:1px solid rgba(6,182,212,.25);
  border-radius:3px;padding:.08rem .35rem;background:rgba(6,182,212,.07);white-space:nowrap}}
::-webkit-scrollbar{{width:5px;height:5px}}
::-webkit-scrollbar-track{{background:var(--bg)}}
::-webkit-scrollbar-thumb{{background:var(--border);border-radius:3px}}
footer{{text-align:center;padding:2rem;color:var(--dim);font-size:.68rem;
  border-top:1px solid var(--border);letter-spacing:.06em}}
</style>
</head>
<body>
<header class="site-header">
  <div class="logo">Static<span>Elf</span> &mdash; XDiff Matrix</div>
  <div class="page-title">Cross-Architecture Similarity Matrix</div>
  <div class="subtitle">{n} binaries &mdash; {n*(n-1)//2} unique pairs compared</div>
</header>
<main class="main">

  <!-- Binary index -->
  <div class="section">
    <div class="section-title">Binaries <span class="count">{n} total</span></div>
    <table class="data">
      <thead><tr><th>#</th><th>Filename</th><th>Machine</th><th>Bits</th><th>Endian</th><th>ELF Type</th><th>ABI</th></tr></thead>
      <tbody>{legend_rows}</tbody>
    </table>
  </div>

  <!-- Heatmap -->
  <div class="section">
    <div class="section-title">Similarity Heatmap</div>
    <div class="heatmap-wrap">
      <table class="heatmap">
        {heatmap_header}
        {heatmap_rows}
      </table>
    </div>
  </div>

  <!-- Ranked pairs + per-signal breakdown -->
  <div class="section">
    <div class="section-title">Ranked Pairs &amp; Signal Breakdown <span class="count">{n*(n-1)//2} pairs</span></div>
    <table class="data">
      <thead>
        <tr>
          <th>#</th><th>Binary A</th><th>Binary B</th>
          <th>Score</th><th>Conf</th>
          {sig_header_cells}
        </tr>
      </thead>
      <tbody>{ranked_rows}</tbody>
    </table>
  </div>

</main>
<footer>Generated by StaticElf XDiff Matrix &mdash; {n} binaries, {n*(n-1)//2} pairs &nbsp;|&nbsp; Produced by Wolfpack Cybernetics</footer>
</body></html>"""


# ------------------------------------------------------------------ #
#  ASM / CFG terminal output                                           #
# ------------------------------------------------------------------ #

def print_asm(az: ELFAnalyzer, top_n: int = 100):
    """Print CFG analysis results for a single binary."""
    asm = az.asm
    name = Path(az.path).name

    if not asm.get("available"):
        print(_color(
            "[!] ASM analysis unavailable — install capstone: pip install capstone",
            _C['RED']
        ))
        return

    if "error" in asm:
        print(_color(f"[!] ASM error: {asm['error']}", _C['RED']))
        return

    print(f"\n{_color('◆ ASM Analysis', _C['BOLD'])}  {_color(name, _C['CYAN'])}")

    _header("Summary")
    _kv("Functions analysed",    str(asm.get("function_count",      0)))
    _kv("Total instructions",    str(asm.get("total_instructions",  0)))
    _kv("Avg instrs / func",     f"{asm.get('avg_instr_per_func',   0.0):.1f}")
    _kv("Avg blocks / func",     f"{asm.get('avg_blocks_per_func',  0.0):.1f}")
    _kv("Avg instrs / block",    f"{asm.get('avg_instr_per_block',  0.0):.1f}")

    top_m = asm.get("top_mnemonics", [])
    if top_m:
        _header("Top Mnemonics")
        for entry in top_m:
            bar = _color("█" * min(entry["count"] * 20 // max(top_m[0]["count"], 1), 30), _C['CYAN'])
            print(f"  {entry['mnemonic']:<12} {entry['count']:>7}  {bar}")

    sem = asm.get("semantic_histogram", {})
    if sem:
        _header("Semantic Distribution")
        total = sum(sem.values()) or 1
        for cat in ("memory","arith","branch","logic","call","ret","other"):
            count = sem.get(cat, 0)
            pct   = count / total
            bar   = _color("█" * int(pct * 40), _C['CYAN'])
            print(f"  {cat:<10} {count:>7}  {pct:>6.1%}  {bar}")

    funcs = asm.get("functions", [])
    if funcs:
        _header(f"Functions  ({len(funcs)} analysed, sorted by size)")
        fmt = "  {:<36} {:>8}  {:>7}  {:>10}"
        print(_color(fmt.format("Function", "Instrs", "Blocks", "Instr/Block"), _C['DIM']))
        print(_color("  " + "─" * 68, _C['DIM']))
        for fn in funcs:
            print(fmt.format(
                fn["name"][:35],
                fn["instr_count"],
                fn["block_count"],
                f"{fn['avg_instr_per_block']:.1f}",
            ))

    print()


# ------------------------------------------------------------------ #
#  CFG HTML report                                                     #
# ------------------------------------------------------------------ #

def generate_cfg_html(az: ELFAnalyzer) -> str:
    """Generate a self-contained dark-theme ASM analysis HTML report."""

    def esc(s):
        return str(s).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")

    asm   = az.asm
    name  = Path(az.path).name
    arch  = az.arch
    funcs = asm.get("functions", [])
    sem   = asm.get("semantic_histogram", {})
    top_m = asm.get("top_mnemonics", [])

    # ── semantic bar chart rows ───────────────────────────────────── #
    total_sem = sum(sem.values()) or 1
    sem_rows  = ""
    for cat in ("memory","arith","branch","logic","call","ret","other"):
        count = sem.get(cat, 0)
        pct   = count / total_sem
        w     = int(pct * 100)
        sem_rows += (f'<tr><td>{cat}</td><td>{count:,}</td>'
                     f'<td><div class="bar-wrap"><div class="bar-fill" style="width:{w}%"></div></div></td>'
                     f'<td>{pct:.1%}</td></tr>')

    # ── mnemonic rows ─────────────────────────────────────────────── #
    max_m = top_m[0]["count"] if top_m else 1
    mnem_rows = ""
    for entry in top_m:
        w = int(entry["count"] / max_m * 100)
        mnem_rows += (f'<tr><td><code>{esc(entry["mnemonic"])}</code></td>'
                      f'<td>{entry["count"]:,}</td>'
                      f'<td><div class="bar-wrap"><div class="bar-fill cyan" style="width:{w}%"></div></div></td></tr>')

    # ── function table rows ───────────────────────────────────────── #
    func_rows = ""
    for fn in funcs:
        func_rows += (f'<tr>'
                      f'<td><code>{esc(fn["name"])}</code></td>'
                      f'<td class="dim">{esc(fn["addr"])}</td>'
                      f'<td>{fn["size"]:,}</td>'
                      f'<td>{fn["instr_count"]:,}</td>'
                      f'<td>{fn["block_count"]}</td>'
                      f'<td>{fn["avg_instr_per_block"]:.1f}</td>'
                      f'</tr>')

    func_count  = asm.get("function_count",     0)
    total_instr = asm.get("total_instructions", 0)
    avg_ipf     = asm.get("avg_instr_per_func", 0.0)
    avg_bpf     = asm.get("avg_blocks_per_func",0.0)
    avg_ipb     = asm.get("avg_instr_per_block",0.0)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>StaticElf ASM — {esc(name)}</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;600;700&family=Syne:wght@400;700;800&display=swap');
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
:root{{
  --bg:#07090c;--bg2:#0d1117;--bg3:#121920;--border:#1a2535;
  --text:#aabbc8;--dim:#3d5068;--accent:#7c3aed;--accent2:#06b6d4;
  --green:#10b981;--yellow:#f59e0b;--red:#f43f5e;--heading:#dde6f0;
}}
html{{font-size:13px}}
body{{background:var(--bg);color:var(--text);font-family:'JetBrains Mono',monospace;line-height:1.55}}
.site-header{{background:linear-gradient(135deg,#07090c 0%,#0d1520 60%,#07090c 100%);
  border-bottom:1px solid var(--border);padding:2rem 3rem 1.75rem}}
.logo{{font-family:'Syne',sans-serif;font-weight:800;font-size:1rem;
  letter-spacing:.15em;text-transform:uppercase;color:var(--accent);margin-bottom:.6rem}}
.logo span{{color:var(--dim)}}
.page-title{{font-family:'Syne',sans-serif;font-weight:700;font-size:1.35rem;
  color:var(--heading);margin-bottom:.35rem}}
.subtitle{{font-size:.78rem;color:var(--dim)}}
.main{{max-width:1100px;margin:0 auto;padding:2rem 3rem 4rem}}
.summary-row{{display:grid;grid-template-columns:repeat(5,1fr);gap:1rem;margin-bottom:2rem}}
.card{{background:var(--bg2);border:1px solid var(--border);border-radius:6px;
  padding:1rem 1.1rem;text-align:center}}
.card-val{{font-family:'Syne',sans-serif;font-size:1.8rem;font-weight:800;
  color:var(--heading);line-height:1}}
.card-lbl{{font-size:.65rem;letter-spacing:.1em;text-transform:uppercase;
  color:var(--dim);margin-top:.35rem}}
.section{{margin-bottom:2rem}}
.section-title{{font-family:'Syne',sans-serif;font-weight:600;font-size:.7rem;
  letter-spacing:.18em;text-transform:uppercase;color:var(--accent);
  margin-bottom:.9rem;padding-bottom:.4rem;border-bottom:1px solid var(--border)}}
table{{width:100%;border-collapse:collapse;font-size:.8rem}}
th{{text-align:left;padding:.4rem .7rem;color:var(--dim);font-weight:400;
  font-size:.68rem;letter-spacing:.07em;text-transform:uppercase;
  border-bottom:1px solid var(--border)}}
td{{padding:.35rem .7rem;border-bottom:1px solid rgba(26,37,53,.7);vertical-align:middle}}
tr:last-child td{{border-bottom:none}}
.dim{{color:var(--dim)}}
code{{font-family:'JetBrains Mono',monospace;font-size:.75rem}}
.bar-wrap{{background:var(--bg3);border-radius:2px;height:6px;width:160px}}
.bar-fill{{height:100%;border-radius:2px;background:var(--accent2)}}
.bar-fill.cyan{{background:var(--accent2)}}
::-webkit-scrollbar{{width:5px;height:5px}}
::-webkit-scrollbar-track{{background:var(--bg)}}
::-webkit-scrollbar-thumb{{background:var(--border);border-radius:3px}}
footer{{text-align:center;padding:2rem;color:var(--dim);font-size:.68rem;
  border-top:1px solid var(--border);letter-spacing:.06em}}
</style>
</head>
<body>
<header class="site-header">
  <div class="logo">Static<span>Elf</span> &mdash; ASM Analysis</div>
  <div class="page-title">{esc(name)}</div>
  <div class="subtitle">
    {esc(arch.get('machine','?'))} {arch.get('bits','?')}-bit
    {arch.get('endianness','?')}-endian &mdash; {esc(arch.get('elf_type','?'))} &mdash;
    entry {esc(arch.get('entry_point','?'))}
  </div>
</header>
<main class="main">

  <div class="summary-row">
    <div class="card"><div class="card-val">{func_count}</div><div class="card-lbl">Functions</div></div>
    <div class="card"><div class="card-val">{total_instr:,}</div><div class="card-lbl">Instructions</div></div>
    <div class="card"><div class="card-val">{avg_ipf:.0f}</div><div class="card-lbl">Avg Instr / Func</div></div>
    <div class="card"><div class="card-val">{avg_bpf:.1f}</div><div class="card-lbl">Avg Blocks / Func</div></div>
    <div class="card"><div class="card-val">{avg_ipb:.1f}</div><div class="card-lbl">Avg Instr / Block</div></div>
  </div>

  <div class="section">
    <div class="section-title">Semantic Distribution</div>
    <table><thead><tr><th>Category</th><th>Count</th><th>Distribution</th><th>%</th></tr></thead>
    <tbody>{sem_rows}</tbody></table>
  </div>

  <div class="section">
    <div class="section-title">Top Mnemonics</div>
    <table><thead><tr><th>Mnemonic</th><th>Count</th><th>Frequency</th></tr></thead>
    <tbody>{mnem_rows}</tbody></table>
  </div>

  <div class="section">
    <div class="section-title">Functions ({func_count} analysed)</div>
    <table><thead><tr>
      <th>Name</th><th>Address</th><th>Size (B)</th>
      <th>Instructions</th><th>Blocks</th><th>Instr/Block</th>
    </tr></thead>
    <tbody>{func_rows}</tbody></table>
  </div>

</main>
<footer>Generated by StaticElf ASM &mdash; {esc(name)} &nbsp;|&nbsp; Produced by Wolfpack Cybernetics</footer>
</body></html>"""


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="staticelf",
        description="StaticElf - Static analysis CLI for ELF binaries",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    p.add_argument("binaries", metavar="BINARY", nargs="*",
                   help="Path(s) to ELF binary/binaries to analyze")

    diff_grp = p.add_argument_group("diff mode")
    diff_grp.add_argument("--diff", metavar=("BINARY_A", "BINARY_B"), nargs=2,
                          help="Diff two ELF binaries (terminal + optional HTML via --out-file)")
    diff_grp.add_argument("--xdiff", metavar="BINARY", nargs="+",
                          help="Cross-arch similarity: 2 binaries = pairwise, 3+ = full N×N matrix")

    scan_grp = p.add_argument_group("bulk scan mode (ML dataset building)")
    scan_grp.add_argument("--scan", "--scan-dir", metavar="DIR",
                          help="Scan a directory of ELF binaries and write one JSON per file")
    scan_grp.add_argument("--out-dir", "--output-dir", metavar="DIR", default=None,
                          help="Output directory for --scan results (required with --scan)")

    asm_grp = p.add_argument_group("assembly analysis")
    asm_grp.add_argument("--asm", metavar="BINARY",
                         help="Deep CFG analysis of a single binary (requires capstone)")
    asm_grp.add_argument("--asm-top-n", metavar="N", type=int, default=100,
                         help="Top-N functions to analyse by size (default: 100)")
    asm_grp.add_argument("--asm-cfg-html", metavar="FILE",
                         help="Write visual CFG HTML report to FILE")

    show = p.add_argument_group("display filters (default: show everything)")
    show.add_argument("--hashes",        action="store_true", help="Show MD5 / SHA256 hashes")
    show.add_argument("--arch",          action="store_true", help="Show architecture info")
    show.add_argument("--security",      action="store_true", help="Show security features")
    show.add_argument("--sections",      action="store_true", help="Show ELF sections table")
    show.add_argument("--imports",       action="store_true", help="Show imported symbols")
    show.add_argument("--entropy",       action="store_true", help="Show entropy values")
    show.add_argument("--strings",       action="store_true", help="Show extracted printable strings")
    show.add_argument("--strings-limit", metavar="N", type=int, default=40,
                      help="Max strings to display (default: 40)")

    out = p.add_argument_group("output format")
    out.add_argument("--output", "-o", choices=["pretty", "json", "csv", "npz"],
                     default="pretty", help="Output format: pretty (default), json, csv, or npz")
    out.add_argument("--out-file", "-f", metavar="FILE", default=None,
                     help="Write output to FILE (required for csv/npz; .html saves HTML diff report)")

    p.add_argument("--min-str-len", metavar="N", type=int, default=4,
                   help="Minimum string length to extract (default: 4)")
    p.add_argument("--no-color", action="store_true", help="Disable ANSI color output")

    return p


# ------------------------------------------------------------------ #
#  ELF magic-byte check                                                #
# ------------------------------------------------------------------ #

_ELF_MAGIC = b"\x7fELF"

def _is_elf(path: Path) -> bool:
    """Return True if the file starts with the ELF magic bytes."""
    try:
        with open(path, "rb") as f:
            return f.read(4) == _ELF_MAGIC
    except OSError:
        return False


# ------------------------------------------------------------------ #
#  Bulk scan engine                                                    #
# ------------------------------------------------------------------ #

def run_scan(scan_dir: str, out_dir: str, min_str_len: int = 4) -> None:
    """
    Scan a flat directory of ELF binaries and write analysis results.

    For each ELF binary found:
        - Runs full ELFAnalyzer.analyze()
        - Writes  <out_dir>/<md5>.json  with complete analysis
        - Appends a row to  <out_dir>/manifest.json
        - On failure, appends a line to  <out_dir>/errors.log

    At completion writes:
        - <out_dir>/summary.json  with counts, arch breakdown, timing stats

    Args:
        scan_dir    (str): Source directory to scan (flat, non-recursive)
        out_dir     (str): Destination directory for all output files
        min_str_len (int): Minimum string length passed to ELFAnalyzer

    Raises:
        ValueError: If scan_dir or out_dir are invalid.
    """
    import time

    scan_path = Path(scan_dir).expanduser().resolve()
    out_path  = Path(out_dir).expanduser().resolve()

    # Validate inputs
    if not scan_path.exists() or not scan_path.is_dir():
        raise ValueError(f"Scan directory does not exist or is not a directory: {scan_dir}")
    if not os.access(scan_path, os.R_OK):
        raise ValueError(f"Scan directory is not readable: {scan_dir}")

    # Create output directory if it doesn't exist
    try:
        out_path.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        raise ValueError(f"Cannot create output directory {out_dir}: {e}") from e
    if not os.access(out_path, os.W_OK):
        raise ValueError(f"Output directory is not writable: {out_dir}")

    # Collect candidate files (flat, no subdirectories)
    candidates = sorted(
        p for p in scan_path.iterdir()
        if p.is_file() and not p.name.startswith(".")
    )

    errors_path   = out_path / "errors.log"
    manifest_path = out_path / "manifest.json"
    summary_path  = out_path / "summary.json"

    manifest = {}   # md5 → { sha256, original_path, arch, ... }
    errors   = []   # { path, reason }

    stats = {
        "total_candidates": len(candidates),
        "total_analyzed":   0,
        "total_skipped":    0,
        "total_errors":     0,
        "arch_counts":      {},
        "machine_counts":   {},
        "bits_counts":      {"32": 0, "64": 0},
        "link_counts":      {"static": 0, "dynamic": 0},
        "verdict_counts":   {"CLEAN": 0, "LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0},
        "high_suspicion":   [],   # list of {md5, path, severity, verdict} for HIGH+CRITICAL
        "elapsed_seconds":  0.0,
    }

    t_start = time.monotonic()

    for i, fpath in enumerate(candidates, 1):
        label = fpath.name
        print(f"  [{i}/{len(candidates)}] {label:<50}", end="\r", flush=True)

        # Skip non-ELF files silently
        if not _is_elf(fpath):
            stats["total_skipped"] += 1
            continue

        try:
            az = ELFAnalyzer(str(fpath), min_str_len=min_str_len)
            result = az.analyze()
        except (ValueError, IOError, OSError) as e:
            stats["total_errors"] += 1
            errors.append({"path": str(fpath), "reason": str(e)})
            continue
        except Exception as e:  # unexpected parser crash — log and continue
            stats["total_errors"] += 1
            errors.append({"path": str(fpath), "reason": f"Unexpected: {e}"})
            continue

        md5    = az.hashes.get("md5", "unknown")
        sha256 = az.hashes.get("sha256", "unknown")

        # Write <md5>.json using ML-optimal flat schema
        json_path = out_path / f"{md5}.json"
        try:
            az.to_ml_json(str(json_path))
        except (IOError, OSError) as e:
            stats["total_errors"] += 1
            errors.append({"path": str(fpath), "reason": f"Write failed: {e}"})
            continue

        # Update manifest
        manifest[md5] = {
            "sha256":       sha256,
            "source_path":  str(fpath),
            "arch_machine": az.arch.get("machine", "?"),
            "arch_bits":    az.arch.get("bits", 0),
            "static":       az.static,
        }

        # Update stats
        stats["total_analyzed"] += 1
        machine = az.arch.get("machine", "unknown")
        bits    = str(az.arch.get("bits", 0))
        link    = az.static

        stats["arch_counts"][machine]  = stats["arch_counts"].get(machine, 0) + 1
        stats["machine_counts"][machine] = stats["machine_counts"].get(machine, 0) + 1
        if bits in stats["bits_counts"]:
            stats["bits_counts"][bits] += 1
        if link in stats["link_counts"]:
            stats["link_counts"][link] += 1

        # IOC verdict tracking
        verdict  = az.iocs.get("verdict", "CLEAN")
        severity = az.iocs.get("severity", 0.0)
        if verdict in stats["verdict_counts"]:
            stats["verdict_counts"][verdict] += 1
        if verdict in ("HIGH", "CRITICAL"):
            stats["high_suspicion"].append({
                "md5":      md5,
                "sha256":   sha256,
                "path":     str(fpath),
                "severity": severity,
                "verdict":  verdict,
            })

    # Clear progress line
    print(" " * 70, end="\r")

    stats["elapsed_seconds"] = round(time.monotonic() - t_start, 3)

    # Write manifest.json
    try:
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)
    except OSError as e:
        print(f"[!] Failed to write manifest.json: {e}", file=sys.stderr)

    # Write errors.log
    if errors:
        try:
            with open(errors_path, "w", encoding="utf-8") as f:
                for err in errors:
                    f.write(f"{err['path']}\t{err['reason']}\n")
        except OSError as e:
            print(f"[!] Failed to write errors.log: {e}", file=sys.stderr)

    # Write summary.json
    try:
        with open(summary_path, "w", encoding="utf-8") as f:
            json.dump(stats, f, indent=2)
    except OSError as e:
        print(f"[!] Failed to write summary.json: {e}", file=sys.stderr)

    # Print final report
    print(f"\n{_color('◆ Scan Complete', _C['BOLD'])}")
    print(f"  Directory   : {scan_path}")
    print(f"  Output      : {out_path}")
    print(f"  Candidates  : {stats['total_candidates']:,}")
    print(f"  Analyzed    : {_color(str(stats['total_analyzed']), _C['GREEN'])}")
    print(f"  Skipped     : {_color(str(stats['total_skipped']), _C['DIM'])}  (non-ELF)")
    print(f"  Errors      : {_color(str(stats['total_errors']), _C['RED'] if stats['total_errors'] else _C['DIM'])}")
    print(f"  Elapsed     : {stats['elapsed_seconds']:.1f}s")
    print()

    if stats["arch_counts"]:
        print(f"  {_color('Architecture breakdown:', _C['DIM'])}")
        for arch, count in sorted(stats["arch_counts"].items(), key=lambda x: -x[1]):
            bar = _color("█" * min(count, 40), _C['CYAN'])
            print(f"    {arch:<16} {count:>5}  {bar}")
    print()

    vc = stats["verdict_counts"]
    print(f"  {_color('IOC verdict breakdown:', _C['DIM'])}")
    for verdict, color in [("CRITICAL", _C['RED']), ("HIGH", _C['RED']),
                            ("MEDIUM", _C['YELLOW']), ("LOW", _C['DIM']), ("CLEAN", _C['GREEN'])]:
        count = vc.get(verdict, 0)
        if count:
            print(f"    {_color(verdict, color):<20} {count:>5}")
    hs = stats["high_suspicion"]
    if hs:
        print(f"\n  {_color(f'{len(hs)} HIGH/CRITICAL binaries flagged — see summary.json → high_suspicion', _C['RED'])}")
    print()

    print(f"  {_color('manifest.json', _C['CYAN'])}  — md5 → sha256 + path index")
    print(f"  {_color('summary.json', _C['CYAN'])}   — counts, arch breakdown, timing")
    if errors:
        print(f"  {_color('errors.log', _C['RED'])}    — {len(errors)} failed files")
    print()


# ------------------------------------------------------------------ #
#  Main                                                                #
# ------------------------------------------------------------------ #

def _validate_out_file(path: str) -> Path:
    """Resolve and validate an output file path. Raises ValueError on bad input."""
    if not path or not path.strip():
        raise ValueError("--out-file must be a non-empty path")
    p = Path(path)
    # Ensure parent directory exists and is writable
    parent = p.parent.resolve()
    if not parent.exists():
        raise ValueError(f"Output directory does not exist: {parent}")
    if not os.access(parent, os.W_OK):
        raise ValueError(f"Output directory is not writable: {parent}")
    return p


def main():
    parser = build_parser()
    args   = parser.parse_args()

    # Validate strings_limit
    if args.strings_limit < 1:
        parser.error("--strings-limit must be at least 1")

    if args.no_color or not sys.stdout.isatty():
        _disable_color()

    # ── ASM MODE ──────────────────────────────────────────────────── #
    if args.asm:
        if not _CAPSTONE:
            print("[!] capstone not installed. Run: pip install capstone", file=sys.stderr)
            sys.exit(1)
        asm_path = Path(args.asm)
        if not asm_path.exists() or not asm_path.is_file():
            print(f"[!] File not found: {args.asm}", file=sys.stderr)
            sys.exit(1)
        try:
            print(f"  Analyzing {asm_path.name} ...")
            az = ELFAnalyzer(str(asm_path), min_str_len=args.min_str_len)
            az.analyze()
            print(f"  Building CFGs (top {args.asm_top_n} functions) ...")
            az.analyze_asm(top_n=args.asm_top_n)
        except (ValueError, IOError, OSError) as e:
            print(f"[!] Analysis failed: {e}", file=sys.stderr)
            sys.exit(1)

        print_asm(az, top_n=args.asm_top_n)

        if args.asm_cfg_html:
            try:
                out_path = _validate_out_file(args.asm_cfg_html)
                html     = generate_cfg_html(az)
                with open(out_path, "w", encoding="utf-8") as f:
                    f.write(html)
                print(f"[OK] CFG HTML report written -> {out_path.resolve()}")
            except (ValueError, OSError) as e:
                print(f"[!] Failed to write CFG HTML: {e}", file=sys.stderr)
                sys.exit(1)
        return

    # ── SCAN MODE ─────────────────────────────────────────────────── #
    if args.scan:
        if not args.out_dir:
            parser.error("--out-dir is required with --scan")
        try:
            run_scan(args.scan, args.out_dir, min_str_len=args.min_str_len)
        except ValueError as e:
            print(f"[!] Scan error: {e}", file=sys.stderr)
            sys.exit(1)
        return
    if args.diff:
        path_a, path_b = Path(args.diff[0]), Path(args.diff[1])
        for p in (path_a, path_b):
            if not p.exists() or not p.is_file():
                print(f"[!] File not found or not a file: {p}", file=sys.stderr)
                sys.exit(1)

        if args.out_file:
            try:
                out_path = _validate_out_file(args.out_file)
            except ValueError as e:
                parser.error(str(e))

        try:
            print(f"  Analyzing {path_a.name} ...")
            az_a = ELFAnalyzer(str(path_a), min_str_len=args.min_str_len)
            az_a.analyze()

            print(f"  Analyzing {path_b.name} ...")
            az_b = ELFAnalyzer(str(path_b), min_str_len=args.min_str_len)
            az_b.analyze()
        except (ValueError, IOError, OSError) as e:
            print(f"[!] Analysis failed: {e}", file=sys.stderr)
            sys.exit(1)

        diff = compute_diff(az_a, az_b)
        print_diff(az_a, az_b, diff, strings_limit=args.strings_limit)

        if args.out_file:
            try:
                if args.output == "json":
                    payload = json.dumps(diff, indent=2)
                    with open(out_path, "w", encoding="utf-8") as f:
                        f.write(payload + "\n")
                    print(f"[OK] Diff JSON written -> {out_path.resolve()}")
                else:
                    html = generate_html_report(az_a, az_b, diff)
                    with open(out_path, "w", encoding="utf-8") as f:
                        f.write(html)
                    print(f"[OK] HTML report written -> {out_path.resolve()}")
            except OSError as e:
                print(f"[!] Failed to write HTML report: {e}", file=sys.stderr)
                sys.exit(1)
        return

    # ── XDIFF MODE ────────────────────────────────────────────────── #
    if args.xdiff:
        xdiff_paths = args.xdiff

        # Validate count
        if len(xdiff_paths) < 2:
            parser.error("--xdiff requires at least 2 binaries")

        # Validate all paths
        for raw in xdiff_paths:
            p = Path(raw)
            if not p.exists() or not p.is_file():
                print(f"[!] File not found or not a file: {raw}", file=sys.stderr)
                sys.exit(1)

        if args.out_file:
            try:
                out_path = _validate_out_file(args.out_file)
            except ValueError as e:
                parser.error(str(e))

        # Analyze all binaries
        analyzers = []
        for raw in xdiff_paths:
            try:
                print(f"  Analyzing {Path(raw).name} ...")
                az = ELFAnalyzer(raw, min_str_len=args.min_str_len)
                az.analyze()
                if _CAPSTONE:
                    print(f"  Building CFGs for {Path(raw).name} ...")
                    az.analyze_asm(top_n=args.asm_top_n if hasattr(args, "asm_top_n") else 100)
                analyzers.append(az)
            except (ValueError, IOError, OSError) as e:
                print(f"[!] Failed to analyze {raw}: {e}", file=sys.stderr)
                sys.exit(1)

        # ── 2 binaries → pairwise xdiff ───────────────────────────── #
        if len(analyzers) == 2:
            xd = compute_xdiff(analyzers[0], analyzers[1])
            print_xdiff(analyzers[0], analyzers[1], xd, strings_limit=args.strings_limit)

            if args.out_file:
                try:
                    if args.output == "json":
                        payload = json.dumps(xd, indent=2)
                        with open(out_path, "w", encoding="utf-8") as f:
                            f.write(payload + "\n")
                        print(f"[OK] XDiff JSON written -> {out_path.resolve()}")
                    else:
                        html = generate_xdiff_html(analyzers[0], analyzers[1], xd)
                        with open(out_path, "w", encoding="utf-8") as f:
                            f.write(html)
                        print(f"[OK] XDiff HTML report written -> {out_path.resolve()}")
                except OSError as e:
                    print(f"[!] Failed to write output: {e}", file=sys.stderr)
                    sys.exit(1)

        # ── 3+ binaries → N×N matrix ──────────────────────────────── #
        else:
            n = len(analyzers)
            total_pairs = n * (n - 1) // 2
            print(f"  Computing {total_pairs} pairs for {n}×{n} matrix ...")
            result = compute_matrix(analyzers)
            print_matrix(result, strings_limit=args.strings_limit)

            if args.out_file:
                try:
                    if args.output == "json":
                        # Serialize matrix result (strip non-serializable signal detail for brevity)
                        payload = json.dumps({
                            "labels": result["labels"],
                            "paths":  result["paths"],
                            "arches": result["arches"],
                            "matrix": result["matrix"],
                            "pairs":  [
                                {k: v for k, v in p.items() if k != "signals"}
                                | {"signals": {s: result["pairs"][i]["signals"][s]["score"]
                                               for s in _XDIFF_WEIGHTS}}
                                for i, p in enumerate(result["pairs"])
                            ],
                        }, indent=2)
                        with open(out_path, "w", encoding="utf-8") as f:
                            f.write(payload + "\n")
                        print(f"[OK] Matrix JSON written -> {out_path.resolve()}")
                    else:
                        html = generate_matrix_html(analyzers, result)
                        with open(out_path, "w", encoding="utf-8") as f:
                            f.write(html)
                        print(f"[OK] Matrix HTML report written -> {out_path.resolve()}")
                except OSError as e:
                    print(f"[!] Failed to write output: {e}", file=sys.stderr)
                    sys.exit(1)
        return
    if not args.binaries:
        parser.print_help()
        sys.exit(1)

    if args.output in ("csv", "npz") and not args.out_file:
        parser.error(f"--out-file is required when --output={args.output}")

    if args.out_file:
        try:
            out_path = _validate_out_file(args.out_file)
        except ValueError as e:
            parser.error(str(e))

    show_all = not any([args.hashes, args.arch, args.security, args.sections,
                        args.imports, args.entropy, args.strings])
    show = lambda flag: show_all or flag

    for binary_path in args.binaries:
        path = Path(binary_path)
        if not path.exists():
            print(f"[!] File not found: {binary_path}", file=sys.stderr)
            continue
        if not path.is_file():
            print(f"[!] Not a file: {binary_path}", file=sys.stderr)
            continue

        try:
            az = ELFAnalyzer(str(path), min_str_len=args.min_str_len)
            az.analyze()
        except (ValueError, IOError, OSError) as e:
            print(f"[!] Failed to analyze {binary_path}: {e}", file=sys.stderr)
            continue

        if args.output == "pretty":
            print_summary(az)
            if show(args.hashes):   print_hashes(az)
            if show(args.arch):     print_architecture(az)
            if show(args.security): print_security(az)
            if show(args.sections): print_sections(az)
            if show(args.imports):  print_imports(az)
            if show(args.entropy):  print_entropy(az)
            if show(args.strings):  print_strings(az, limit=args.strings_limit)
            print()

        elif args.output == "json":
            result = {
                "path":      str(path),
                "file_size": az.file_size,
                "static":    az.static,
                "arch":      az.arch,
                "hashes":    az.hashes,
                "security":  az.security,
                "entropy":   az.entropy,
                "sections":  az.sections,
                "imports":   az.imports,
                "strings":   az.strings,
            }
            try:
                payload = json.dumps(result, indent=2)
            except (TypeError, ValueError) as e:
                print(f"[!] Failed to serialize results for {binary_path}: {e}", file=sys.stderr)
                continue

            if args.out_file:
                try:
                    with open(out_path, "w", encoding="utf-8") as f:
                        f.write(payload + "\n")
                    print(f"[OK] JSON written to {out_path}")
                except OSError as e:
                    print(f"[!] Failed to write JSON: {e}", file=sys.stderr)
            else:
                print(payload)

        elif args.output == "csv":
            try:
                written = az.to_pandas_csv(args.out_file)
                print(f"[OK] CSV row appended -> {written}")
            except (IOError, OSError) as e:
                print(f"[!] Failed to write CSV: {e}", file=sys.stderr)

        elif args.output == "npz":
            try:
                written = az.to_numpy_npz(args.out_file)
                print(f"[OK] NPZ written -> {written}")
            except (IOError, OSError, ImportError) as e:
                print(f"[!] Failed to write NPZ: {e}", file=sys.stderr)


if __name__ == "__main__":
    main()
