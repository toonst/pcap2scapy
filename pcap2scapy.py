#!/usr/bin/env python3
"""pcap2scapy_refactored.py — turn a packet capture (pcap/pcapng) into a
stand‑alone Scapy replay script based on an external template.
"""
from __future__ import annotations

import argparse
from collections.abc import Sequence
from datetime import datetime, timezone
from pathlib import Path

from scapy.all import Packet, Raw, rdpcap  # type: ignore
import scapy.fields as scapy_fields

ChecksumField = getattr(scapy_fields, "ChecksumField", type("ChecksumField", (), {}))
LenField = getattr(scapy_fields, "LenField", scapy_fields.Field)
FieldLenField = getattr(scapy_fields, "FieldLenField", scapy_fields.Field)
FieldListField = getattr(scapy_fields, "FieldListField", scapy_fields.Field)
RandFieldBase = getattr(scapy_fields, "RandFieldBase", type("RandFieldBase", (), {}))
RandField = getattr(scapy_fields, "RandField", type("RandField", (), {}))
ConditionalField = getattr(scapy_fields, "ConditionalField", scapy_fields.Field)

INDENT = " " * 4
AUTO_GENERATED_FIELDS = (ChecksumField, LenField, FieldLenField)

PROTOCOL_FIELD_EXCLUSIONS: dict[str, set[str]] = {
    "Ether": {"src", "dst", "type"},
    "IP": {"ihl", "len", "chksum", "id", "proto"},
    "UDP": {"len", "chksum"},
    "TCP": {"chksum", "dataofs"},
}


def has_random_default(field) -> bool:
    from types import FunctionType

    return isinstance(field.default, (RandFieldBase, RandField, FunctionType))


def should_skip_field(layer: Packet, field) -> bool:
    if field.name in PROTOCOL_FIELD_EXCLUSIONS.get(layer.__class__.__name__, set()):
        return True

    while isinstance(field, ConditionalField):
        field = field.fld

    if isinstance(field, AUTO_GENERATED_FIELDS):
        return True

    if field.default is None:
        return True

    if getattr(field, "islist", False) and not layer.getfieldval(field.name):
        return True

    if has_random_default(field):
        return True

    try:
        if hasattr(field, "is_default"):
            return field.is_default(layer)
        return layer.getfieldval(field.name) == field.default
    except Exception:
        return False


def inline_layer(layer: Packet) -> str:
    chunks: list[str] = []
    for field in layer.fields_desc:
        if should_skip_field(layer, field):
            continue
        value = layer.getfieldval(field.name)
        chunks.append(f"{field.name}={repr(value)}")
    body = ", ".join(chunks)
    return f"{layer.__class__.__name__}({body})" if body else f"{layer.__class__.__name__}()"


def format_value(value, current_indent: str) -> str:
    if isinstance(value, list):
        if not value:
            return "[]"
        nested_indent = current_indent + INDENT
        rendered = [
            nested_indent + (inline_layer(v) if isinstance(v, Packet) else repr(v))
            for v in value
        ]
        return "[\n" + ",\n".join(rendered) + "\n" + current_indent + "]"
    if isinstance(value, Packet):
        return inline_layer(value)
    return repr(value)


def layer_to_code(layer: Packet, base_indent: str) -> str:
    rendered: list[str] = []
    for field in layer.fields_desc:
        if should_skip_field(layer, field):
            continue
        value = layer.getfieldval(field.name)
        rendered.append(f"{field.name}={format_value(value, base_indent + INDENT)}")

    if not rendered:
        return f"{layer.__class__.__name__}()"

    inner = (",\n" + base_indent + INDENT).join(rendered)
    return f"{layer.__class__.__name__}(\n{base_indent + INDENT}{inner}\n{base_indent})"


def packet_to_code(packet: Packet, index: int) -> str:
    layers: list[str] = []
    current: Packet | None = packet
    while current and isinstance(current, Packet) and not isinstance(current, Raw):
        layers.append(layer_to_code(current, INDENT))
        current = current.payload if isinstance(current.payload, Packet) else None
    body = ("/\n" + INDENT).join(layers)
    return f"pkt{index} = (\n{INDENT}{body}\n)"


def render_packets(packets: Sequence[Packet]) -> tuple[str, str, str]:
    definitions: list[str] = []
    names: list[str] = []
    timestamps: list[str] = []

    for index, packet in enumerate(packets, start=1):
        definitions.append(packet_to_code(packet, index))
        names.append(f"pkt{index}")
        timestamps.append(str(packet.time))

    return "\n\n".join(definitions), ", ".join(names), ", ".join(timestamps)


def apply_template(template_path: Path, **kwargs) -> str:
    return template_path.read_text(encoding="utf-8").format(**kwargs)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Convert pcap/pcapng capture to a stand‑alone Scapy replay script",
    )
    parser.add_argument("capture", help="Input pcap/pcapng file")
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="Output .py file (default: <capture>_replay.py)",
    )
    parser.add_argument(
        "--template",
        type=Path,
        help="Template path (default: template.py.tmpl next to this script)",
    )
    return parser.parse_args()


def main() -> None:  # pragma: no cover
    args = parse_args()

    capture_path = Path(args.capture).expanduser()
    if not capture_path.is_file():
        raise SystemExit(f"Capture not found: {capture_path}")

    packets = rdpcap(str(capture_path))
    if not packets:
        raise SystemExit("Capture is empty — nothing to convert")

    output_path = args.output or capture_path.with_name(f"{capture_path.stem}_replay.py")

    template_path = args.template or Path(__file__).with_name("template.py.tmpl")
    if not template_path.is_file():
        raise SystemExit(f"Template not found: {template_path}")

    packet_defs, packet_names, packet_times = render_packets(packets)
    timestamp_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    script_body = apply_template(
        template_path,
        timestamp=timestamp_iso,
        packet_definitions=packet_defs,
        pkt_list=packet_names,
        time_list=packet_times,
    )

    output_path.write_text(script_body, encoding="utf-8")
    output_path.chmod(output_path.stat().st_mode | 0o111)

    print(
        f"Created {output_path} ({len(packets)} packets).\n"
        f"Run with, e.g.:\n  sudo python {output_path} -i eth0",
    )


if __name__ == "__main__":
    main()
