#!/usr/bin/env python3
"""
pcap2scapy.py — convert a .pcap/.pcapng trace into a clean Scapy replay
script, using an external Jinja-style template (template.py.tmpl).

Features
~~~~~~~~
• Emits per-packet code that lists **only non-default field values** and uses
  multi-line formatting for readability.
• The generated replay script relies on **argparse** so you pass the interface
  (`-i/--iface`) at runtime
• Optional flags: preserve original inter-packet timing (`--delta`) and loop
  forever (`--loop`).

Usage
~~~~~
    python pcap2scapy.py capture.pcapng              # → capture_replay.py
    python pcap2scapy.py trace.pcap -o custom.py     # specify output name
    python pcap2scapy.py trace.pcap --delta          # template populated with timing

The template file **must live next to this script** and be named
`template.py.tmpl` (or override with `--template`).
"""
from __future__ import annotations

import argparse
import pathlib
import textwrap
from datetime import datetime, timezone
from typing import List, Sequence

from scapy.all import rdpcap, Packet, Raw  # type: ignore

# ---------------------------------------------------------------------------
# Which fields we can safely omit because Scapy fills them in
# ---------------------------------------------------------------------------
AUTO_SKIP = {
    'Ether': {'src', 'dst', 'type'},
    'IP': {'ihl', 'len', 'id', 'frag', 'flags', 'chksum', 'proto'},
    'UDP': {'len', 'chksum'},
    'TCP': {'dataofs', 'reserved', 'window', 'urgptr', 'chksum', 'len', 'seq', 'ack'},
}

INDENT = " " * 4  # 4‑space indent per nesting level

# ---------------------------------------------------------------------------
# Pretty‑printing helpers
# ---------------------------------------------------------------------------

def _inline_layer(layer: Packet) -> str:
    """Return *single‑line* constructor of *layer* (used inside lists)."""
    parts = []
    skip = AUTO_SKIP.get(layer.__class__.__name__, set())
    for fld in layer.fields_desc:
        if fld.name in skip:
            continue
        val = getattr(layer, fld.name)
        try:
            if val == fld.default:
                continue
        except Exception:
            pass
        parts.append(f"{fld.name}={repr(val)}")
    inner = ", ".join(parts)
    return f"{layer.__class__.__name__}({inner})" if inner else f"{layer.__class__.__name__}()"


def _fmt_value(val, indent: str) -> str:
    """Return printable repr for *val*, pretty‑indenting lists of Packets."""
    if isinstance(val, list):
        if not val:
            return "[]"
        inner_indent = indent + INDENT
        rendered_items = []
        for item in val:
            if isinstance(item, Packet):
                rendered_items.append(inner_indent + _inline_layer(item))
            else:
                rendered_items.append(inner_indent + repr(item))
        return "[\n" + ",\n".join(rendered_items) + "\n" + indent + "]"
    elif isinstance(val, Packet):
        return _inline_layer(val)
    else:
        return repr(val)


def _layer_to_code(layer: Packet, base_indent: str) -> str:
    """Return *multi‑line* constructor for *layer* with nice indentation."""
    skip = AUTO_SKIP.get(layer.__class__.__name__, set())

    field_strings: List[str] = []
    for fld in layer.fields_desc:
        if fld.name in skip:
            continue
        value = getattr(layer, fld.name)
        try:
            if value == fld.default:
                continue
        except Exception:
            pass
        field_strings.append(f"{fld.name}={_fmt_value(value, base_indent + INDENT)}")

    if not field_strings:
        return f"{layer.__class__.__name__}()"

    inner = (",\n" + base_indent + INDENT).join(field_strings)
    return f"{layer.__class__.__name__}(\n{base_indent + INDENT}{inner}\n{base_indent})"


def pkt_to_code(pkt: Packet, idx: int) -> str:
    """Return a fully formatted *pkt<idx>* definition."""
    layers: List[str] = []
    current: Packet | None = pkt
    while current and isinstance(current, Packet) and not isinstance(current, Raw):
        layers.append(_layer_to_code(current, INDENT))
        current = current.payload if isinstance(current.payload, Packet) else None

    body = ("/\n" + INDENT).join(layers)
    return f"pkt{idx} = (\n{INDENT}{body}\n)"

# ---------------------------------------------------------------------------
# Template rendering
# ---------------------------------------------------------------------------

def build_packet_code(pkts: Sequence[Packet]):
    defs, names, times = [], [], []
    for i, p in enumerate(pkts, 1):
        defs.append(pkt_to_code(p, i))
        names.append(f"pkt{i}")
        times.append(str(p.time))
    return "\n\n".join(defs), ", ".join(names), ", ".join(times)


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------

def render_template(tmpl: str, **kw) -> str:
    return tmpl.format(**kw)


def main():  # pragma: no cover
    ap = argparse.ArgumentParser(description="Convert a capture to a Scapy replay script")
    ap.add_argument("capture", help="pcap/pcapng file to convert")
    ap.add_argument("-o", "--output", help="output .py file")
    ap.add_argument("--template", help="template path (default: template.py.tmpl)")
    args = ap.parse_args()

    cap = pathlib.Path(args.capture).expanduser()
    if not cap.is_file():
        ap.error(f"capture not found: {cap}")

    pkts = rdpcap(str(cap))
    if not pkts:
        ap.error("capture is empty — nothing to convert")

    out = pathlib.Path(args.output) if args.output else cap.with_name(cap.stem + "_replay.py")
    tmpl = pathlib.Path(args.template) if args.template else pathlib.Path(__file__).with_name("template.py.tmpl")
    if not tmpl.is_file():
        ap.error(f"template not found: {tmpl}")

    pkt_defs, pkt_names, time_vals = build_packet_code(pkts)
    iso_ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    replay_code = render_template(
        tmpl.read_text(encoding="utf-8"),
        timestamp=iso_ts,
        packet_definitions=pkt_defs,
        pkt_list=pkt_names,
        time_list=time_vals,
    )

    out.write_text(replay_code, encoding="utf-8")
    out.chmod(out.stat().st_mode | 0o111)

    print(
        textwrap.dedent(
            f"""
            Created {out}  ({len(pkts)} packets).\nRun with, e.g.:\n  sudo python {out} -i eth0
            """
        ).strip()
    )


if __name__ == "__main__":
    main()
