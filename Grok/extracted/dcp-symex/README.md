# dcp-symex

Offline RE helpers for T8140 iOS 27 DCP RPC catalog.

## What ran
- `scan_tags.py` — find A/D fourCC immediates in kext disasm
- `emu_lookup.py` — unicorn-emulate D→AP lookup functions (PAC ops skipped) → `d_handlers.json`
- `handler_sizes.py` — min in/out from cmp gates
- `strrefs.py` / deep string walk — name recovery
- `a_calls.py` — AP→DCP call-site sizes
- `build_catalog.py` → `/workspace/dcp-rpc-catalog.json` + markdown

## angr
Not used successfully: these kexts are arm64e (PACIBSP/AUTDA/BLRAA everywhere). Default angr has no faithful PAC model for this XNU kext ABI. Fallback was unicorn concrete execution of the *lookup* functions (works) and guided disassembly of reply consumers (`setDCPAVPropEnd`, `hotPlug_notify_gated`).

A full angr project would need: custom Claripy hooks for PAC, a fake object graph for IOMFB instances, and IOKit OSUnserializeXML — out of scope vs guided RE payoff.
