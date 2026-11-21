# JackTrace

**Which port is this jack? Ask the switch.**

JackTrace is a free, open-source tool for IT techs. Plug a Windows laptop into a wall jack, run JackTrace, and it tells you which switch and port that jack is patched to, along with the VLAN, voice VLAN, PoE and the switch's management IP. No toner, no ladder, no digging through the patch panel.

![License: MIT](https://img.shields.io/badge/license-MIT-2b7de9)
![Windows 11 | 10](https://img.shields.io/badge/Windows-11%20%7C%2010-2b7de9?logo=windows)
![Status: v0.2 preview](https://img.shields.io/badge/status-v0.2%20preview-f2a93b)

> **Status:** v0.2 preview. It finds the switch port on Windows 10/11 and has been tested against real hardware, but it's young. See [Planned](#planned) for what comes next.

---

## What it looks like

```
C:\> jacktrace

┌─ JackTrace v0.2.1 ───────────────────────────┐
│ heard IDF2-ACCESS-01 via LLDP · checking fo… │
│ ██████████░░░░░░░░  0:34 / 2:00              │
└──────────────────────────────────────────────┘

  switch   IDF2-ACCESS-01  (Cisco C9200L-48P-4G)
  port     Gi1/0/24   "Room 114 desk"
  vlan     20 data · 120 voice
  mgmt     10.0.20.2
  poe      15.4 W
  link     1000BASE-T full
  via      CDP + LLDP on Ethernet (Intel Ethernet Connection I219-V)
```

The box redraws every second while JackTrace listens. Lines only appear when the switch actually sent that detail.

## How to use it

1. Plug the laptop into the jack you want to trace.
2. Run `jacktrace.exe`. It asks for administrator rights (Windows' packet capture needs them). Double-clicking works; the window stays open until you press Enter.
3. Wait. Most switches answer within 30 seconds; JackTrace gives up after 2 minutes.

JackTrace stops as soon as it has what the switch is going to send: right away for non-Cisco switches (only Cisco sends CDP), or after giving the other protocol one full interval when a Cisco switch has only been heard on one.

| Option | What it does |
|---|---|
| `--ticket` | Prints a plain block to paste into a helpdesk ticket |
| `--json` | Prints every announcement as JSON, for scripts |
| `--adapter <text>` | Only listens on adapters whose name, description or MAC contains `<text>` |
| `--timeout <time>` | Longest to listen, e.g. `90s` or `3m` (default `2m`) |
| `-v` | Shows capture details |
| `--version` | Prints the version |

Exit codes: `0` found a switch · `3` heard nothing · `1` error · `130` stopped with Ctrl+C.

## Walk mode: audit a whole floor

```
C:\> jacktrace walk 2nd-floor.csv

JackTrace walk mode → C:\audits\2nd-floor.csv
Plug into a jack, type its label, press Enter. Type q when you're done.

Jack label [q = done]: R114-01
✓ R114-01 → IDF2-ACCESS-01 Gi1/0/24 · VLAN 20, voice 120

Jack label [Enter = R114-02, r = redo R114-01, q = done]:
✓ R114-02 → IDF2-ACCESS-01 Gi1/0/24 · VLAN 20, voice 120
  ⚠ Same port as R114-01. Did the cable move? Is the jack mislabeled?
```

- **Labels count up for you:** `R114-09` → `R114-10`, `2-114A` → `2-114B`. Press Enter to accept, type your own, `r` to redo the last jack, `q` to finish.
- **Saved after every jack.** Closing the window or a dead battery never loses work. Run the same command again to carry on where you stopped.
- **Flags mix-ups:** a jack that lands on a port already recorded gets a warning and a note in the file.
- **Opens cleanly in Excel,** one row per jack: `jack, status, switch, port, port_description, vlan, voice_vlan, mgmt_ip, poe_w, link, model, via, adapter, heard_at, note`. If the file is open in Excel when JackTrace saves, it keeps your results and saves again after the next jack.

Tip: Excel can turn a port like `1/3` into a date. Use Data → From Text/CSV and set the port column to Text.

## How it works

Managed switches announce themselves on every port, every 30 to 60 seconds, using **CDP** (Cisco Discovery Protocol) and **LLDP** (Link Layer Discovery Protocol). JackTrace listens for those announcements and decodes them.

- **No driver to install.** It uses `pktmon`, the packet capture tool built into Windows 10 (1809+) and Windows 11.
- **Leaves no trace.** It won't start if another pktmon capture is running, and it always stops its capture and removes its filters when it's done, even after Ctrl+C.
- **No IP address needed.** Announcements arrive even on a jack with no DHCP.
- **One exe.** No installer.

## Planned

- Plain-English hints for more "nothing heard" cases (NICs that swallow LLDP, VMs, and so on)
- Npcap support for faster live capture when it's already installed
- A small window for people who'd rather not use a terminal

## Credits

JackTrace is inspired by [LDWin](https://github.com/chall32/LDWin) by Chris Hall (2010–2015), a tool many techs carried on their USB sticks for years. JackTrace is a fresh implementation written from the public CDP and LLDP specifications. It contains no LDWin code.

## License

[MIT](LICENSE)
