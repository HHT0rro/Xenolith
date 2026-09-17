# Fuzzing (TASK-037)

cargo-fuzz targets over the raw-bytes attack surface. Malformed input must
be rejected with an error, never panic, never hang.

| Target | Surface |
|---|---|
| `pe_parse` | `Pe64::parse` + exports/imports/relocs/TLS/import-name locations |
| `elf_parse` | `elf::parse` + program headers, DT_INIT, IFUNC/TLS/version census, symtab stats, packed bootstrap detection |
| `envelope_parse` | `EnvelopeV2` decode (protocol core + loader wrapper) — truncation/overflow/version mismatch fail closed |
| `inspect_bytes` | full classify + report path (`xenolith inspect`) |

## Run (bounded smoke)

On Windows hosts cargo-fuzz needs nightly; the MSVC target has no bundled
ASan runtime, so the smoke runs execute in WSL (or any Linux box) where the
toolchain works out of the box. Leak detection is disabled:
`iced_x86` keeps one-time `lazy_static` decoder tables alive for the whole
process, which LSan flags at exit — a global-init false positive, not an
input-dependent leak (verified: `-runs=1000` on an empty corpus leaks 0).

```
export CARGO_TARGET_DIR=$HOME/.cache/xl-fuzz-target   # keep artifacts off drvfs
cargo +nightly fuzz run pe_parse       -- -max_total_time=60 -timeout=5 -rss_limit_mb=2560 -detect_leaks=0
cargo +nightly fuzz run elf_parse      -- -max_total_time=60 -timeout=5 -rss_limit_mb=2560 -detect_leaks=0
cargo +nightly fuzz run envelope_parse -- -max_total_time=60 -timeout=5 -rss_limit_mb=2560 -detect_leaks=0
cargo +nightly fuzz run inspect_bytes  -- -max_total_time=60 -timeout=5 -rss_limit_mb=2560 -detect_leaks=0
```

First smoke (2026-09-08, 4×60 s) executed >9.3M total inputs and surfaced
seven input-safety defects — all fixed as checked/saturating arithmetic or
allocation guards, all in `fuzz/fixtures/` replaying clean:

| Target | Finding | Fix |
|---|---|---|
| pe_parse | `hint_name + 2` u32 overflow in import-name scrub + imports | `checked_add` fail-closed |
| pe_parse | export name/ord/func table RVA arithmetic overflow | `checked_add` fail-closed |
| pe_parse | `ordinal_base + ordinal_index` u32 overflow (display field) | `wrapping_add` |
| elf_parse | `vaddr_to_off`: `va + filesz` and `off + delta` u64 overflow | `checked_add` fail-closed |
| elf_parse | `p_vaddr + filesz` in RX ranges; symtab section/symbol walks | `saturating_add` |
| elf_parse | `cstr_at_off`: `base + off` / `base + len` overflow | checked + clamped limit |
| envelope_parse | 17 GB `Vec::with_capacity` from attacker counts (regions/imports/keep/relocs) | count × min-record ≤ remaining bytes |

## Regression fixtures

Every crash found by any run is committed under `fuzz/fixtures/<target>/`
(the generated corpus and artifacts dirs stay gitignored). A fixture stays
forever; CI replays the fixtures on every change. Continuous fuzzing runs
on the scheduled workflow (see `.github/workflows/ci.yml`), not on every PR.
