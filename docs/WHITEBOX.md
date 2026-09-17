# White-box threat model (W0)

This is the contract for Xenolith's selected-export virtualization. It is a defense index, not an unpacker or exploit guide. Strength claims that are not in this file, [SUPPORT.md](SUPPORT.md), or the CI gate table in [README.md](../README.md) are not claims.

The packed-image runtime is the PIC stub `pack()` emits. `xenolith-loader` is a host emulator. `xenolith-runtime` is not in the image.

## W0

The attacker has:

1. The packed PE.
2. **This repository** (GPL). Handler shapes, MBA identities, lift rules, and the PIC stub are not secret.
3. Professional reverse-engineering practice: unpackers, tracers, dumpers, Hex-Rays/Ghidra, VTIL-class IR.
4. Unlimited AI-agent assistance (IDA/Ghidra MCP, tracers, lifters, training on self-packed samples).

GPL consequence: **"custom ISA not in LLM training data" is not a security claim.** The model can read this tree and pack its own samples.

What W0 does *not* give the attacker: a reusable `xenolith-devirt` that, given only the public tree plus one packed binary, recovers every protected function as a stable ISA. Source knowledge yields a **meta-compiler / per-handler symbolic engine**. Cost must scale with the protected function, not with "learn the VM once".

## What commercial VMs actually leak (public)

Xenolith does **not** clone these architectures. The rows exist so we do not re-import a publicly lifted design.

| Product (public) | What a generic lifter latches onto | Why cloning it is a W0 regression |
| --- | --- | --- |
| VMProtect 3.x | Shared handler table; VIP/VSP; rolling key; pattern-matchable handlers (push-imm, add, read, jmp, …); `VMENTER` | [NoVmp](https://github.com/can1357/NoVmp) lifts x64 3.0–3.5 to VTIL **without packer source**. A known handler table is exactly what a white-box attacker trains on. |
| Themida / Code Virtualizer | Multiple mutually incompatible VM *skeletons* (TIGER/FISH/LION/…); per-build mutation of registers/opcodes; still a **handler table + bytecode stream** | Extra skeletons raise per-binary labor. They do not remove the "find dispatcher, classify handlers" loop. Oreans' own docs warn against inserting every VM (size) and to rotate architecture over versions. |
| Virbox Protector | Layered encrypt / obfuscate / function VM / RASP. 2026 marketing: five AI dependencies (quality pseudocode, string/API anchors, stable CFG, debugger loop, reusable experience). Vendor observation that top models stay in the 20–36% band after OLLVM SUB+FLA+BCF, and "VM ~3%", is **not** a Xenolith metric | "Private ISA not in training data" dies under GPL. OLLVM-class mutation is W1/W2, not a phase change. |

Idea sources (not copied code): public UPX notes, published VMProtect/Themida unpacker writeups, [NoVmp](https://github.com/can1357/NoVmp), Oreans Code Virtualizer help, Virbox public product/AI articles, ChimeraVMP writeups (sharded AEAD + scratch window), JavaShroud CASE (offline unwrap).

## Forbidden design (would make W0 *easier*)

- Shared handler table indexed by a stable opcode.
- Global guest bytecode (`GuestMap` / `XLGVM` stream) in the packed image.
- Central dispatcher / interpret loop (`l_gloop`: `movzx eax,[rsi]; inc rsi; cmp eax,imm; je handler`).
- Treating "looks like VMProtect" as a milestone.
- Arming executable-page C2 while it breaks G-BEH.
- Whole-`.text` / CRT / `DllMain` virtualization.
- Exposing unarmed switches in `--help` or the TUI.

The key-mix VM (`XLVMOP\x01`, envelope `ENV_OPCODES`) stays a **stub unpack** machine. It is not the user-code VM and must not share an opcode map with it.

## What we build instead

Pack-time compiler, not a language:

```
selected export
  → iced-x86 CFG (fail-closed: no mem/call/rip-rel/SEH; cmp+jcc fused to BrCmp)
  → pack-internal IR (never written to the image; not a guest ISA)
  → one SuperOp per basic block
  → unique PIC per block (schedule / one-cut MBA / seed junk)
  → thunk saves non-volatile GPRs, jumps to the entry block
  → block edges are direct jmp/jcc (W1 isomorphic to the original CFG)
  → original export is jmp rel32 or a retargeted export RVA
```

"VM" means **this pack emits a new program**. There is no reusable opcode table across packs.

## Honest staging

| Stage | Blocks | Does not block |
| --- | --- | --- |
| **W1 / W2** | Generic `GuestMap` lifter; NoVmp-style "find dispatcher, classify handlers"; a cross-seed opcode→semantics table | An analyst/AI **reading mutated x64**; a trace whose CFG is **isomorphic** to the original (W2 keeps CFG); training "block → semantics" on this source |
| **W3** (`--trace-diverge`) | Same input, unstable instruction stream; naive trace alignment is broken. Coin: TEB ⊕ heap ⊕ RSP, not RDTSC. See [ENTROPY.md](ENTROPY.md). | Per-binary, per-block symbolic execution / manual recovery (cost grows with block count). A debugger that pins heap and stack can still align. |
| **Never claimed** | Irreversibility; VMProtect parity; a paused process cannot read the currently decrypted page; CI "unlimited AI failed" | |

W1/W2 are in the OLLVM band: unique native handlers, **still a readable CFG**. **W3 (`--trace-diverge`) is implemented**: refuse naive trace alignment. That is not irreversibility and not commercial-grade. Do not advertise otherwise.

W1/W2 **must not** introduce a central dispatcher in order to look more like a commercial VM. That would be a regression under W0.

## Product honesty

The CLI and TUI expose **only wired options**. A flag that is a no-op is a defect. `--trace-diverge` is wired (flags + TUI + project file). C2, full C1 (never-write FirstThunk), and string encryption do not appear.

`--vm-export` virtualizes **named exports** only. CRT and `DllMain` stay native. EXE files with no named exports cannot be virtualized in W1.

## Residual (unchanged)

See [POLICY.md](POLICY.md) and [TECHNIQUES.md](TECHNIQUES.md). C2 remains unarmed (G-BEH veto). Disk import directory RVA is 0; runtime still writes original IAT slots. Seed hex is never printed in reports.
