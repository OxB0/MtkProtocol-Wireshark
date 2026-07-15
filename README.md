# MTK Wireshark Scripts

Lua dissector for MediaTek **XFlash** (V5) USB protocol 

## Setup

Drop `xflash.lua` into your Wireshark plugins folder and reload (`Ctrl+Shift+L`):

- Windows: `%APPDATA%\Wireshark\plugins`
- Linux/macOS: `~/.local/lib/wireshark/plugins` (or `~/.config/wireshark/plugins`)

Capture the USB traffic with USBPcap (Windows) or usbmon (Linux). **Turn off any
snap length / "capture only first N bytes"** — otherwise large image transfers are
truncated (the dissector still tracks them via `usb.data_len`, but you won't get the
image bytes; see "Truncated captures" below).

## Making a capture easy to read

**Flow view.** Open **Analyze ▸ Expert Information** for a clean chronological list
of every command / response.

**Progress column.** Right-click the column header ▸ *Column Preferences* ▸ **+** ▸
Type `Custom`, Field `xflash.progress`. You'll see `714 MB / 4094 MB (17%)` inline
while scrolling.

**Coloring.** Import `mtk_xflash.colorfilters` via **View ▸ Coloring Rules ▸
Import…** — errors red, image chunks green, commands blue, reads purple.

**Flash summary.** **Tools ▸ MTK XFlash ▸ Flash summary** shows, per partition,
bytes written / chunk count / % of total and any error statuses. Works even on a
partial capture.

Reassembly fragments are intentionally not tagged as `xflash`, so the `xflash`
filter already shows only real frames.
