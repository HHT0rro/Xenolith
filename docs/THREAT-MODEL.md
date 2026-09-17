# Threat model

This is the product threat model for Xenolith. It restates who the
attacker is, what the defender may assume, and what is **out of scope**.
White-box staging for selected-export superoperators remains in
[WHITEBOX.md](WHITEBOX.md).

## Assets

- The packed AMD64 image the customer ships.
- Selected functions the customer asked to transform.
- Import names and read-only constants **only when** a later stage can prove
  a complete reference set (not current).
- Optional kernel-assist policy, when deployed and signed (not current).

Not an asset we claim to hide from a white-box attacker: packer source
(GPL-3.0-or-later), handler shapes, MBA identities, lift rules, PIC stub
bytes, or keys that the local executable must hold in order to run.

## Attacker (W0, always on)

The attacker has:

1. The packed binary.
2. This repository.
3. Ordinary reverse-engineering tools (disassemblers, tracers, dumpers,
   Hex-Rays/Ghidra, VTIL-class IR).
4. Unlimited AI-agent assistance, including packing their own samples from
   this tree.

The attacker does **not** need a secret ISA. "Not in LLM training data" is
not a claim under GPL.

## Defender assumptions

- The OS loader, kernel, and hypervisor are trusted **unless** the customer
  explicitly deploys kernel-assist, in which case the assist is still not a
  defense against a malicious kernel or hypervisor.
- The packed program is allowed to run. We do not hide the process, kill
  other processes, unload security software, or patch on-disk `ntdll`.
- ASLR/PIE, DEP/NX, W^X, Windows CFG/CET, and Linux RELRO stay on. Compatibility
  must not be bought by turning them off.
- Production cryptography, when G1 lands, is AEAD with an explicit AAD
  range. FNV, API hashes, MBA, and split keys are **not** confidentiality
  proofs.

## In scope (target, not all current)

| Goal | Meaning | Current tree |
| --- | --- | --- |
| Raise cost of generic VM lifting | No shared handler table, no `GuestMap` stream, no `l_gloop` in the image | Selected-export PIC only |
| Raise cost of naive trace alignment | W3 `--trace-diverge`, TEB⊕heap⊕RSP coin | Implemented; identical stream hashes in one run are still allowed by the old gate |
| Honest packing | Fail closed on unsupported semantics | Yes for mem/call/rip-rel/SEH/ELF |
| Limit long-term plaintext | Dormant protected regions wiped; no long-term RWX | **Partial**: stub and restored pages are RX (temporary RW then RX). After unpack, executable pages stay plaintext. C2 re-encrypt is not jumped to |
| Protect proven import sites / constants | Separate Windows IAT and Linux GOT/PLT models | Disk import directory RVA 0 + writeback only |
| Optional kernel access control | Signed callbacks / supported LSM; `off/optional/required` | Absent |

## Out of scope (never claimed)

- Irreversibility, "unlimited AI failed", or commercial VMProtect / Themida parity.
- Resistance to an analyst who reads the mutated x64, or who symbolically
  executes each superoperator block.
- A paused process that cannot read the currently executable page.
- Absolute anti-dump against full process access, malicious kernel, hypervisor,
  or physical memory.
- Hiding the program from the administrator of the machine.
- Moving the user program to Ring 0.
- Generic kernel or process memory read/write APIs.
- JIT, self-modifying code, overlapping instruction streams, self-checksum
  code, and unauthenticated ISA extensions.
- Completeness on an arbitrary stripped binary with indirect control flow
  and no symbols / unwind info.

## Trust boundaries

```
customer source / input binary
        │  packer (untrusted to the attacker; known under W0)
        ▼
packed image on disk     ← ciphertext pages + envelope + PIC stub
        │  system loader (trusted)
        ▼
mapped image in the victim process
        │  PIC stub decrypts in place (current: stays decrypted)
        ▼
executable pages + original IAT slots filled
```

`xenolith-loader` sits **outside** this boundary. It is a host model for
tests. A green emulator run is not evidence that the packed file loaded on
Windows or Linux.

## Kernel-assist (future, optional)

When G7 exists, kernel-assist is an **access-control helper** on a trusted OS:

- Windows: documented object-access callbacks, signed, HVCI-compatible (no
  dynamic kernel code, no W+X). Device interface: ACL, caller auth, length
  checks, version negotiation. No generic memory R/W. Registration binds a
  process object, not a raw PID.
- Linux: dumpability, application core-dump policy, supported LSM. Not a
  default machine-wide ptrace change. Not an unsigned `.ko` pretending to be
  an LSM.

Modes: `off` (no connection), `optional` (report fallback), `required` (refuse
to run protected work if assist cannot be established). Missing signatures or
missing isolated test machines make G7 **blocked**, not "complete + kernel".

## Residual risks (current and remaining after G8)

- Semantic recovery of a selected export remains possible; cost is meant to
  scale with the function, not drop to zero.
- The executing page is readable.
- White-box knowledge of this tree yields a per-handler symbolic engine.
- Stripping ASLR (current pack) collapses image-derived entropy; see
  [ENTROPY.md](ENTROPY.md).
- A debugger that pins TEB/heap/RSP can still align W3 traces.
- GuestMap decode failure is not proof against de-virtualization of unique
  native handlers.
