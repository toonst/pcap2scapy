#!/usr/bin/env python3
"""
pcap2scapy.py — convert a capture (pcap / pcapng) into a lean, readable
Scapy‑replay script, using an external *str.format* template.

"""
from __future__ import annotations

import argparse
import pathlib
import textwrap
from datetime import datetime, timezone
from typing import List, Sequence

from scapy.all import rdpcap, Packet, Raw  # type: ignore
# Import field classes in a way that works across Scapy versions
import scapy.fields as _scapy_fields

ChecksumField   = getattr(_scapy_fields, 'ChecksumField', type('DummyChecksum', (), {}))
LenField        = getattr(_scapy_fields, 'LenField', _scapy_fields.Field)
FieldLenField   = getattr(_scapy_fields, 'FieldLenField', _scapy_fields.Field)
FieldListField  = getattr(_scapy_fields, 'FieldListField', _scapy_fields.Field)
RandFieldBase    = getattr(_scapy_fields, 'RandFieldBase', type('DummyRandFieldBase', (), {}))
RandField        = getattr(_scapy_fields, 'RandField', type('DummyRandField', (), {}))
ConditionalField = getattr(_scapy_fields, 'ConditionalField', _scapy_fields.Field)

INDENT = " " * 4  # 4‑space indent throughout

# ---------------------------------------------------------------------------
# Generic rule: drop anything Scapy will re‑create (checksums, lengths, etc.)
# ---------------------------------------------------------------------------

AUTO_FIELD_CLASSES = (
    ChecksumField,
    LenField,
    FieldLenField,
)

# Per-protocol overrides
ALWAYS_SKIP: dict[str, set[str]] = {
    "Ether": {"src", "dst", "type"},
    "IP": {"ihl", "len", "chksum", "id", "proto"},
    "UDP": {"len", "chksum"},
    "TCP": {"chksum", "dataofs"},
}

_IP_AUTO_PROTO = { "UDP": 17, "TCP": 6, "ICMP": 1 }


def _is_rand_default(fld) -> bool:
    """True if the field's default is any Rand* instance or a callable."""
    from types import FunctionType
    return isinstance(fld.default, (RandFieldBase, RandField)) or isinstance(fld.default, FunctionType)

def _should_skip(layer: Packet, fld) -> bool:
    """Return True if *fld* can be omitted without altering replay behaviour."""

    # 0. ─── explicit user table ───────────────────────────────────────────────
    if fld.name in ALWAYS_SKIP.get(layer.__class__.__name__, ()):
        return True

    # unwrap nested ConditionalField objects
    while isinstance(fld, ConditionalField):
        fld = fld.fld

    # 1. IP-specific heuristics ----------------------------------------------
    if layer.__class__.__name__ == "IP":
        if fld.name in {"src", "dst"} :
            return False

    # 2. ─── scapy will rewrite these in post_build ───────────────────────────
    if isinstance(fld, AUTO_FIELD_CLASSES):
        return True
    if fld.default is None:                        # len, ihl, chksum, ...
        return True

    # 3. ─── empty list-type fields (FieldListField, PacketListField, …) ──────
    if getattr(fld, "islist", False) and not layer.getfieldval(fld.name):
        return True


    # 4. ─── random / callable defaults (Rand*, lambda, etc.) ─────────────────
    if _is_rand_default(fld):
        return True

    # 5. ─── value equals the protocol default ────────────────────────────────
    try:
        if hasattr(fld, "is_default"):
            return fld.is_default(layer)
        return layer.getfieldval(fld.name) == fld.default
    except Exception:
        return False
# ---------------------------------------------------------------------------
# Pretty‑printing helpers
# ---------------------------------------------------------------------------

def _inline_layer(layer: Packet) -> str:
    """One‑liner representation for nested packets (RRs, options, …)."""
    parts = []
    for fld in layer.fields_desc:
        if _should_skip(layer, fld):
            continue
        val = layer.getfieldval(fld.name)
        parts.append(f"{fld.name}={repr(val)}")
    inner = ", ".join(parts)
    return f"{layer.__class__.__name__}({inner})" if inner else f"{layer.__class__.__name__}()"


def _fmt_value(val, indent: str) -> str:
    """Pretty‑print lists & nested packets with indentation."""
    if isinstance(val, list):
        if not val:
            return "[]"
        inner_indent = indent + INDENT
        rendered = [
            inner_indent + (_inline_layer(v) if isinstance(v, Packet) else repr(v))
            for v in val
        ]
        return "[\n" + ",\n".join(rendered) + "\n" + indent + "]"
    elif isinstance(val, Packet):
        return _inline_layer(val)
    else:
        return repr(val)


def _layer_to_code(layer: Packet, base_indent: str) -> str:
    """Multi‑line pretty constructor for *layer*."""
    fields: List[str] = []
    for fld in layer.fields_desc:
        if _should_skip(layer, fld):
            continue
        value = layer.getfieldval(fld.name)
        fields.append(f"{fld.name}={_fmt_value(value, base_indent + INDENT)}")

    if not fields:
        return f"{layer.__class__.__name__}()"

    inner = (",\n" + base_indent + INDENT).join(fields)
    return f"{layer.__class__.__name__}(\n{base_indent + INDENT}{inner}\n{base_indent})"


def pkt_to_code(pkt: Packet, idx: int) -> str:
    """Return fully formatted ``pkt<idx>`` definition."""
    layers: List[str] = []
    current: Packet | None = pkt
    while current and isinstance(current, Packet) and not isinstance(current, Raw):
        layers.append(_layer_to_code(current, INDENT))
        current = current.payload if isinstance(current.payload, Packet) else None

    body = ("/\n" + INDENT).join(layers)
    return f"pkt{idx} = (\n{INDENT}{body}\n)"

# ---------------------------------------------------------------------------
# Template helpers
# ---------------------------------------------------------------------------

def build_packet_code(pkts: Sequence[Packet]):
    defs, names, times = [], [], []
    for i, p in enumerate(pkts, 1):
        defs.append(pkt_to_code(p, i))
        names.append(f"pkt{i}")
        times.append(str(p.time))
    return "\n\n".join(defs), ", ".join(names), ", ".join(times)


def render_template(tmpl: str, **kw) -> str:
    return tmpl.format(**kw)

# ---------------------------------------------------------------------------
# CLI driver
# ---------------------------------------------------------------------------

def main() -> None:  # pragma: no cover
    ap = argparse.ArgumentParser(description="Convert a capture to a Scapy replay script")
    ap.add_argument("capture", help="pcap/pcapng file to convert")
    ap.add_argument("-o", "--output", help="output .py file (default: <stem>_replay.py)")
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

    defs, names, times = build_packet_code(pkts)
    iso_ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    replay_code = render_template(
        tmpl.read_text(encoding="utf-8"),
        timestamp=iso_ts,
        packet_definitions=defs,
        pkt_list=names,
        time_list=times,
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
