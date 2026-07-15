<h1 align="center">MTK Wireshark Scripts</h1>

<p align="center"><i>Lua dissectors for MediaTek XFlash (V5) &amp; XMLFlash (V6) USB protocols</i></p>

<img width="3186" height="1034" alt="image" src="https://github.com/user-attachments/assets/a9658c03-b073-40c2-9df0-fe61252a6d42" />

## Which script?

There are three plugins — you only need **one**:

| File | Handles |
|------|---------|
| **`mtk_da.lua`** | **both V5 and V6, auto-detected** |
| `xflash.lua` | V5 (XFlash) only | if for some reason there is a bug with the auto detect try this
| `xmlflash.lua` | V6 (XMLFlash) only | same


## Setup

Drop your chosen script `mtk_da.lua` into your Wireshark plugins folder and reload (`Ctrl+Shift+L`):

- Windows: `%APPDATA%\Wireshark\plugins`
- Linux/macOS: `~/.local/lib/wireshark/plugins` (or `~/.config/wireshark/plugins`)

Capture the USB traffic with USBPcap (Windows) or usbmon (Linux).

## Making a capture easy to read

**Flow view.** Open **Analyze ▸ Expert Information** for a clean chronological list
of every command / response.

**Coloring.** Import `mtk_xflash.colorfilters` via **View ▸ Coloring Rules ▸
Import…** — errors red, image chunks green, commands blue, reads purple.

**Summary** Tools -> MTK DA -> your protocol

Reassembly fragments are intentionally not tagged
