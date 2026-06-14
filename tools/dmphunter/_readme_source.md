# dmpHunter

> Hunt indicators inside Windows **mini/full** process dumps: memory maps, handles, threads, modules (+ IAT), strings, sockets↔threads, YARA, and surgical VA-range dumping.

- Primary CLI: **`dmph`**  
- Secondary: **`dmpHunter`**  
- Back-compat alias: **`mdr`**

---

## Table of Contents

- [Features](#features)
- [Install](#install)
- [Quick Start](#quick-start)
- [Selectors & Exporters](#selectors--exporters)
- [Command Reference](#command-reference)
  - [memmap](#memmap)
  - [handles](#handles)
  - [threads](#threads)
  - [modules](#modules)
  - [strings](#strings)
  - [scan](#scan)
  - [net](#net)
  - [dump](#dump)
  - [dump-json](#dump-json)
  - [dump-csv](#dump-csv)
- [Recipes / How-tos](#recipes--how-tos)
- [Troubleshooting](#troubleshooting)
- [Performance Tips](#performance-tips)
- [FAQ](#faq)
- [Contributing & License](#contributing--license)

---

## Features

- **Mini & Full dump support** (unified VA→file mapping from MemoryList, Memory64List, and **Thread stacks**).
- **Memory map** with decoded protection, **start/end** VAs, CSV/JSON export.
- **Handles** with **decoded access masks** (process & thread), verify `PROCESS_SUSPEND_RESUME`.
- **Threads** with TEB and **StackStart/StackEnd**.
- **Modules** and **IAT** (import table) parsing.
- **Strings** (ASCII + UTF-16LE), incl. **VA-range** scanning (`--start/--end|--length`) and **command line** heuristics.
- **YARA**: streaming scan over selected regions (**no huge allocations**).
- **Network heuristics**: socket-like handles ↔ threads + endpoints scanned from stacks.
- **Dump VA ranges**: robust streamer that **crosses discontiguous segments**; great for stacks/heap pages.

---

## Install

Requires Python **3.9+** (Linux/macOS/Windows). Works cross-platform for analysis; Windows is only needed to create the dumps.

```bash
# from the repo root (contains pyproject.toml)
pip install -e .

# Optional: enable YARA features
pip install -e .[yara]
```

Check it:
```bash
dmph --help
# or
dmpHunter --help
# or (alias)
mdr --help
```

---

## Quick Start

```bash
# 1) Overview: memory map, handles, threads, modules → JSON
dmph dump-json process.dmp triage.json

# 2) Memory map with IMAGE regions → CSV
dmph memmap process.dmp --region-type IMAGE --csv mem.csv

# 3) Handles (decode access), verify PROCESS_SUSPEND_RESUME
dmph handles process.dmp --handle-type Process --verify

# 4) Threads & their stack ranges
dmph threads process.dmp

# 5) Modules + IAT
dmph modules process.dmp --iat

# 6) Strings (all committed PRIVATE), show only likely command lines
dmph strings process.dmp --region-type PRIVATE --committed-only --cmdlines --min-len 5

# 7) YARA stream scan (committed by default)
dmph scan process.dmp --yara rules.yar --region-type PRIVATE --writable-only

# 8) Per-thread network heuristics
dmph net process.dmp

# 9) Dump a precise VA range (inclusive)
dmph dump process.dmp --start 0x7FF600000000 --end 0x7FF600001FFF --out chunk.bin

# or start + length
dmph dump process.dmp --start 0x0000022DF0000000 --length 65536 --out region.bin
```

---

## Selectors & Exporters

**Selectors** (supported by several commands):
- `--region-type PRIVATE|MAPPED|IMAGE`
- `--writable-only` (RW / WRCOPY / XRW / XWRCOPY)
- `--rwx-only` (PAGE_EXECUTE_READWRITE only)
- `--committed-only` (MEM_COMMIT)

**Exporters**
- `--json out.json` (on `memmap`)
- `--csv out.csv` (on `memmap`)
- Dedicated: `dump-json`, `dump-csv`

---

## Command Reference

### `memmap`

Show memory regions with **Start VA**, **End VA**, **Size**, **State**, **Type**, **Protect** (decoded).

```bash
dmph memmap <dump> [--region-type IMAGE|PRIVATE|MAPPED] [--writable-only] [--rwx-only]
                [--committed-only] [--limit N] [--json out.json] [--csv out.csv]
```

Example:
```bash
dmph memmap process.dmp --region-type IMAGE --json mem.json
```

---

### `handles`

List handles; for process/thread types show **decoded** access flags.  
`--verify` prints whether any Process handle has `PROCESS_SUSPEND_RESUME`.

```bash
dmph handles <dump> [--handle-type TEXT] [--verify]
```

Examples:
```bash
dmph handles process.dmp
dmph handles process.dmp --handle-type Process --verify
```

---

### `threads`

List threads with TEB and **stack start/end** (use with `dump` or `strings --start/--end`).

```bash
dmph threads <dump>
```

---

### `modules`

List modules. With `--iat`, print import table per module (up to 5000 symbols per module to keep output readable).  
Supports fuzzy filter: `--module "contains:<text>"`.

```bash
dmph modules <dump> [--iat] [--module "contains:<text>"]
```

Examples:
```bash
dmph modules process.dmp --iat
dmph modules process.dmp --iat --module "contains:ws2_32.dll"
```

---

### `strings`

Stream-extract **ASCII & UTF-16LE** strings. Two modes:

1) **Region-driven** (default; respects selectors)  
2) **VA-range** via `--start/--end` or `--start/--length` (overrides selectors)

```bash
dmph strings <dump>
    [--min-len N]
    [--region-type TYPE] [--writable-only] [--rwx-only] [--committed-only]
    [--cmdlines] [--limit N]
    [--start 0xVA] [--end 0xVA] [--length N]
```

Examples:
```bash
# Query likely command lines across committed PRIVATE regions
dmph strings process.dmp --region-type PRIVATE --committed-only --cmdlines --min-len 5

# Scan a specific VA interval (e.g., a thread stack or heap page)
dmph strings process.dmp --start 0x0000022DF0000000 --length 65536 --min-len 6
```

---

### `scan`

**Streaming YARA** over selected regions (no huge buffers).  
Default `--committed-only` is **True**.

```bash
dmph scan <dump> --yara rules.yar
    [--region-type TYPE] [--writable-only] [--rwx-only] [--committed-only/--no-committed-only]
```

Examples:
```bash
dmph scan process.dmp --yara cobalt.yar
dmph scan process.dmp --yara rules.yar --region-type PRIVATE --writable-only
```

> Install extras first: `pip install -e .[yara]`

---

### `net`

Heuristically correlates **socket-like handles** to **threads**, and scans each thread’s **stack** for IP endpoints (sockaddr patterns + textual `a.b.c.d:port`).

```bash
dmph net <dump> [--handle-type Socket]
```

---

### `dump`

Dump raw bytes for a **VA range**. Streams across discontiguous segments (MemoryList / Memory64 / Thread stacks). Skips unmapped holes.

```bash
dmph dump <dump> --start 0xVA [--end 0xVA | --length N] --out file.bin
```

Examples:
```bash
# Dump full thread stack
dmph threads process.dmp
dmph dump process.dmp --start 0x<StackStart> --end 0x<StackEnd> --out stack.bin

# Dump 64 KB from a heap page
dmph dump process.dmp --start 0x7FF600000000 --length 65536 --out page.bin
```

---

### `dump-json`

One-shot JSON triage: memmap, handles (decoded), threads, modules, plus a convenience flag `verify_PROCESS_SUSPEND_RESUME`.

```bash
dmph dump-json <dump> <out.json>
```

---

### `dump-csv`

Memory map → CSV (respects selectors).

```bash
dmph dump-csv <dump> <out.csv>
    [--region-type TYPE] [--writable-only] [--rwx-only] [--committed-only]
```

---

## Recipes / How-tos

### Identify the thread that’s beaconing to C2
```bash
# 1) See sockets and endpoints per thread (stack-scan)
dmph net process.dmp

# 2) Inspect suspect thread’s stack range
dmph threads process.dmp

# 3) Dump stack to file (for manual strings/YARA)
dmph dump process.dmp --start 0x<StackStart> --end 0x<StackEnd> --out stack.bin

# 4) Find strings in that exact range
dmph strings process.dmp --start 0x<StackStart> --end 0x<StackEnd> --min-len 5
```
If you find pointers (addresses) on the stack that look like buffers, match them to **PRIVATE, RW** regions (`dmph memmap`) and dump those pages.

### Focus on code/heap regions likely to hold payload/config
```bash
# Committed, writable PRIVATE regions are prime suspects
dmph memmap process.dmp --region-type PRIVATE --writable-only --committed-only --csv mem.csv

# Strings across those regions
dmph strings process.dmp --region-type PRIVATE --writable-only --committed-only --min-len 6 --limit 1000

# YARA signatures (streaming)
dmph scan process.dmp --yara malware_rules.yar --region-type PRIVATE --writable-only
```

### Walk imports for a given module (IAT)
```bash
dmph modules process.dmp --iat --module "contains:winhttp"
```

### Export everything quickly and work with `jq`
```bash
dmph dump-json process.dmp triage.json
jq '.threads[] | {tid, stack_start, stack_end}' triage.json
```

---

## Troubleshooting

**`dump` wrote 0 bytes**  
- Fixed in **v0.2.0** by streaming across segments and including thread stacks in the VA map.  
- If you still get 0 bytes, the requested VA range may not exist in the dump. Try the thread’s stack or an IMAGE region address you see in `memmap`.

**`ValueError: Invalid RVA/size:`**  
- A stream descriptor points beyond the file bounds (truncated/custom dumps).  
- Capture a **Full** dump if possible. If reproducible on a known-good dump, please open an issue with the dump’s stream list.

**No endpoints in `net` but Process Explorer shows a connection**  
- Works best with **Full** dumps. The thread may not have had the handle or sockaddr on its stack at capture time.  
- Try again near the beacon interval; or dump the thread’s stack and search for IPs/ports.

**YARA not found**  
```bash
pip install -e .[yara]
```

---

## Performance Tips

- Use **selectors** to reduce scanned memory (`--region-type PRIVATE --writable-only --committed-only`).  
- Prefer **VA-range** mode for `strings` when you already know the stack/page to look at.  
- Keep YARA rules focused; avoid massive rule-sets unless needed.

---

## FAQ

**Does this show plaintext C2 config?**  
Not necessarily. Code is usually present in clear in a running dump, but configs are often obfuscated/encrypted or “sleep-masked.” Use `dmph` to target the **right pages**, then run a dedicated **config extractor** on the dumped bytes.

**Mini vs Full dumps?**  
Full dumps retain much more memory (stacks, heaps), improving `net`, `strings`, and YARA results. Mini dumps may omit the relevant pages.

**Can I pipe output into my own tooling?**  
Yes—use `dump-json`, `dump-csv`, or dump the exact VA ranges (`dump`) for post-processing.

---

### Version

This README targets **dmpHunter v0.2.0**. For help at the CLI:
```bash
dmph --help
dmph <subcommand> --help
```
