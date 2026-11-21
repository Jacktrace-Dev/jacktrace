# JackTrace brand: "patch panel"

JackTrace is its own brand, not part of PC-BUILT. The look borrows from the hardware it's about: a dark network rack, Cat6 blue cable, and the amber and green LEDs on a switch port.

Consult the maintainer before changing anything here.

## Name and voice

- **Name:** JackTrace (one word, capital J and T). The command is lowercase: `jacktrace`.
- **Tagline:** "Which port is this jack? Ask the switch."
- **Alternate line:** "Trace the jack. Skip the toner."
- **Voice:** a calm senior tech. Short, plain sentences. Name the real cause when something fails ("This switch port isn't sending LLDP") instead of a generic error.

## Colors

| Token | Dark | Light | Used for |
|---|---|---|---|
| `--rack` | `#16181c` | `#f4f5f7` | Page and window background |
| `--panel` | `#22262c` | `#ffffff` | Cards, the boxed CLI frame |
| `--rail` | `#3a3f47` | `#d5d9df` | Borders, dividers |
| `--cat6` | `#2b7de9` | `#1f66c6` | Primary accent, links, the trace line |
| `--activity` | `#f2a93b` | `#b76e00` | Listening, progress, "waiting for the switch" |
| `--link-up` | `#3ccf6e` | `#1c8a45` | Found it, success |
| `--fault` | `#e5484d` | `#c62a2f` | Errors |
| `--text` | `#e8eaed` | `#16181c` | Body text |
| `--muted` | `#9aa1ab` | `#5b626c` | Labels, secondary text |

The amber/green pairing is the hook: amber means "listening", green means "link found", the same way a switch port's LEDs read.

## Terminal colors

| State | ANSI color |
|---|---|
| Frame and headings | blue (`--cat6`) |
| Listening, countdown bar | yellow (`--activity`) |
| Result values once found | green (`--link-up`) |
| Field labels (`switch`, `port`...) | default/dim |
| Errors and hints | red, then plain text for the hint |

Respect `NO_COLOR` and non-terminal output: no color codes when piped.

## Type

- **Code and CLI:** JetBrains Mono.
- **Website body:** Inter.

## Icon

The front of an RJ45 jack on a rack-charcoal tile, with amber contacts and a Cat6-blue trace leaving the jack and ending in a green link LED. Draft: [assets/icon.svg](assets/icon.svg).

## CLI layout

```
 ┌─ JackTrace v0.1 ─────────────────────────┐
 │ listening on Ethernet (Intel I219-V)…    │
 │ ██████████░░░░░░░░  0:34 / 2:00          │
 └──────────────────────────────────────────┘

  switch   IDF2-ACCESS-01  (Cisco C9200L-48P)
  port     Gi1/0/24   "Room 114 desk"
  vlan     20 data · 120 voice
  mgmt     10.0.20.2
  poe      15.4 W class 3
  via      CDP + LLDP
```

Labels are lowercase and left-aligned in one column; values line up in a second column.
