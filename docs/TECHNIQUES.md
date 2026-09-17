# Technique map (clean-room)

Each row is a public unpacker step and the corresponding Xenolith counter. This is a defense index, not an exploit guide.

The injected PIC stub (`pack/src/stub.rs`) decrypts mapped pages in place with XOR, checks a keyed FNV-1a digest over those bytes (G-TAMPER), then junks the in-memory section table and lies about `SizeOfImage` (C3-lite). Host-side HMAC page MACs still exist in the packer and in `xenolith-loader` (a test model, not the product runtime); the PIC stub does **not** compute SHA-256 HMAC. `xenolith-runtime` is a separate unused cryptosystem.

| Public step | Counter | Xenolith module |
| --- | --- | --- |
| UPX section names / stub signature | Per-build mutation, random section names, no `UPX0/1` | pack |
| DIE/YARA packer families | Best-effort string scan (no UPX/Themida/VMP section names); not a DIE install | pack |
| Dump 32-byte identity and `SHA-256(id\|\|ASCII)` | MBA immediates + image measurement; no contiguous master key | crypto |
| Static IAT window | Disk import directory RVA is 0 on `standard`/`max`; stub hashed-resolve then **writes VAs back** into original IAT slots | pack + PIC stub |
| OEP hunt / `jmp` back to original `.text` | Stolen entry bytes + delayed bind; packed entry is the PIC stub | pack + vm |
| IAT write breakpoint (Scylla) | Disk table empty. PIC stub still writes resolved VAs into original IAT slots so CRT `DllMain` works; a write-breakpoint during unpack remains a residual | PIC stub |
| Full dump of decrypted `.text` | In-place XOR of mapped pages; keyed FNV digest before use. Envelope keep-list exists but **executable-page C2 is not armed**: encrypting any `.text` page of the hello_dll sample broke `hello_add`. Dump of `.text` after unpack is still plaintext. Not a decryption window | pack + PIC stub |
| Dump is a loadable PE | In-memory section-table scramble + `SizeOfImage` lie. MZ and export directory are kept so `GetProcAddress` works | PIC stub |
| Paste dumped pages into the file | Host HMAC page MAC on the envelope; PIC stub verifies keyed FNV, not SHA-256 HMAC | crypto |
| External RPM scan of the module | Stub probes on `max`; CI does not attach RPM | guard |
| Debugger attach / Frida spawn | `max` stub: PEB.BeingDebugged, HideFromDebugger, ProcessDebugPort, ProcessDebugObjectHandle, ProcessDebugFlags, INT3 on NtQuery. No user-mode `mov drN`. CI does not attach a debugger or Frida | stub |
| Linear F5 of decrypt loop | PIC stub walks a per-build opcode map (`load_imm`/`mix_key`/`halt`) to reconstruct MBA limbs; Newton inverse still lives in the `mix_key` handler | pack + stub |
| F5 of a selected export (`--vm-export`) | Native body is retargeted into per-block unique PIC (superoperators). Pack-internal IR is not a guest ISA and is not written to the image. No central `l_gloop` dispatcher. CRT / `DllMain` stay native. W2: per-block RA / schedule / MBA. W3 `--trace-diverge`: two equal paths, TEB⊕heap⊕RSP coin ([ENTROPY.md](ENTROPY.md)). Not whole-`.text` | pack + vm + stub |
| White-box generic lifter / shared opcode table (W0) | Each pack is a new program: unique handlers, no reusable `GuestMap` (G-WB-NOLIFT / G-WB-DIVERSE / G-WB-META). **Does not** stop an analyst or AI reading mutated x64. W3 breaks naive trace alignment, not per-block SE. Staging in [WHITEBOX.md](WHITEBOX.md) | docs + pack + vm |

Sources of *ideas* (not copied code): public UPX unpack notes, published VMProtect/Themida unpacker writeups, [NoVmp](https://github.com/can1357/NoVmp) (why a shared handler table is a white-box gift), ChimeraVMP sharded AEAD + scratch window, JavaShroud CASE offline unwrap. See [WHITEBOX.md](WHITEBOX.md).
