# pcap2scapy

`pcap2scapy` converts any **PCAP** or **PCAP‑NG** network capture into a fully‑functional, human‑readable **Scapy** replay script.

> *“Turn captured packets back into code – tweak, replay, study.”*

---

## ✨  Highlights

| Feature                  | Details                                                                                                 |
| ------------------------ | ------------------------------------------------------------------------------------------------------- |
| **Template‑driven**      | Uses an external Jinja‑style template so you can completely control the look of generated scripts.      |
| **Auto‑clean packets**   | Drops MAC addresses, checksums, lengths and other auto‑fillable fields; keeps only what matters.        |
| **Pretty printing**      | Multi‑line, indented output – even verbose layers like DNS or TLS stay readable.                        |
| **Timing & looping**     | Generated scripts can preserve original inter‑packet gaps (`--delta`) and loop indefinitely (`--loop`). |
| **Interface at runtime** | No hard‑coded NIC; pass `-i wlan0` (or similar) when you run the replay.                                |
| **Little dependencies**  | Requires only Scapy ≥ 2.5 and Python ≥ 3.8.                                                             |

---

## 📦  Installation

```bash
git clone https://github.com/toonst/pcap2scapy.git
cd pcap2scapy
pip install -r requirements.txt
```

The repository contains:

```
pcap2scapy.py           # the converter
template.py.tmpl        # default template used by the converter
```

---

## 🛠  Usage

```bash
python pcap2scapy.py [-h] [--template TEMPLATE] [-o OUTPUT] capture.pcap[ng]
```

| Option         | Purpose                                                         |
| -------------- | --------------------------------------------------------------- |
| `capture`      | Input capture file (PCAP or PCAP‑NG).                           |
| `-o, --output` | Output replay script name (default: `<capture>_replay.py`).     |
| `--template`   | Path to a custom template (default: `replay_template.py.tmpl`). |

### Generated replay script options

```
-i, --iface   <name>   # interface to transmit on (required)
--delta               # honour original time gaps between packets
--loop                # send the burst forever
```

---

## ⚖️  Legal / Ethical notice

Replaying or spoofing packets can disrupt networks and may violate local laws or organisational policies. **Run generated scripts only in controlled environments or with explicit permission.** The authors disclaim all liability.

---

## 🤝  Contributing

Everyone is welcome! Feel free to open issues or pull requests for:

* bug fixes & improvements
* support for new protocols / smarter field‑skipping
* documentation & examples

Please follow the existing coding style and include tests where feasible.

---

## 📄  License

Released under the **MIT License**

---

## 🙏  Acknowledgements

Built on the shoulders of the excellent [**Scapy**](https://scapy.net/) project.

