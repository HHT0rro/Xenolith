# W3 coin entropy

G3 restores `IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE` / `HIGH_ENTROPY_VA`
when they were present on the input. The system loader applies ASLR to
the packed image. Relocs that land in EnvelopeV2-protected pages are
re-applied by `xl_core` after AEAD open (DIR64 only). The W3 coin still
must not use image-derived RIP: TEB ⊕ heap ⊕ RSP remain the selector.
The injected PIC stub + `xl_core` is the runtime; the host
`xenolith-loader` crate is not.

`--trace-diverge` must not use those as the path selector. RDTSC is also
forbidden as the sole coin (timing is a G-BEH hazard and a tracer can
pin it).

## Coin (wired)

At the start of each superoperator block:

```
r11 = TEB            ; gs:[0x30]
r10 = PEB.ProcessHeap ; gs:[0x60]+0x18
r11 ^= r10
r11 ^= RSP
ZF = r11.bit0 after a seed-dependent shift
```

`r10` is saved/restored. `r11` is the dedicated TMP (not in the alloc
pool). No `rdtsc`.

TEB, the user heap, and the thread stack still move under system ASLR
even when the packed image does not. Two ordinary processes with the
same input can therefore take different paths and still return the same
eax (`eval_ir`).

## Residual

A debugger that pins heap and stack (or a clone of an identical address
space) can still align traces. W3 claims **process-unique streams under
normal load**, not that a paused process with frozen TEB/heap/RSP is
unalignable. Per-block symbolic execution of this pack remains possible;
cost scales with block count.

See [WHITEBOX.md](WHITEBOX.md).
