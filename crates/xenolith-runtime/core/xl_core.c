/* Freestanding EnvelopeV2 + ChaCha20-Poly1305 core.
 * No CRT, no globals, no imports. All host APIs arrive through XlHostCtx.
 * Reloc-free: no static storage, no string literals.
 */

#include <stdint.h>

#if defined(_MSC_VER)
#define XL_NOINLINE __declspec(noinline)
#else
#define XL_NOINLINE __attribute__((noinline, used))
#endif

/* The core is freestanding on both object paths. MSVC's loop-idiom
 * recognition still lowers variable-length copies to memcpy/memset, so keep
 * local definitions for both compilers instead of depending on CRT. */
XL_NOINLINE void *memcpy(void *dst, const void *src, uint64_t n) {
    volatile uint8_t *d = (volatile uint8_t *)dst;
    const volatile uint8_t *s = (const volatile uint8_t *)src;
    uint64_t i;
    for (i = 0; i < n; i++) d[i] = s[i];
    return dst;
}

XL_NOINLINE void *memset(void *dst, int value, uint64_t n) {
    volatile uint8_t *d = (volatile uint8_t *)dst;
    uint64_t i;
    for (i = 0; i < n; i++) d[i] = (uint8_t)value;
    return dst;
}

#ifndef XL_PAGE_RW
#define XL_PAGE_RW 0x04u
#define XL_PAGE_RX 0x20u
#define XL_PAGE_RWX 0x40u
#define XL_PLATFORM_PE64 0u
#define XL_PLATFORM_ELF64 1u
#define XL_PLATFORM_ELF64_AARCH64 2u
/* Maximum sealed-region plaintext/ciphertext length. Mirrors
 * xenolith_protocol::XL_MAX_REGION (16384) — covers 16-KiB chunks on
 * 16-KiB-page Android devices. The two constants must stay identical;
 * every core-side length gate uses this, never a bare 4096. */
#define XL_MAX_REGION 16384u
#endif



typedef void *(*xl_load_fn)(const char *);
typedef void *(*xl_gpa_fn)(void *, const char *);
typedef int (*xl_vp_fn)(void *, uint64_t, uint32_t, uint32_t *);
/* Module-directory-first dependency resolution (see xl_resolve_moddir). */
typedef uint32_t (*xl_gmfn_fn)(void *, char *, uint32_t);      /* GetModuleFileNameA */
typedef void *(*xl_llx_fn)(const char *, void *, uint32_t);    /* LoadLibraryExA(name, hFile, flags) */

typedef struct XlHostCtx {
    uint8_t *image_base;
    uint8_t *envelope;
    uint32_t envelope_len;
    uint32_t original_entry_rva;
    uint8_t debug_gate;
    uint8_t _pad[7];
    uint8_t measurement[32];
    xl_load_fn load_library;
    xl_gpa_fn get_proc;
    xl_vp_fn vprotect;
    void *veh_handle;   /* G5: AddVectoredExceptionHandler registration */
    void *(*veh_remove)(void *); /* G5: RemoveVectoredExceptionHandler */
    xl_gmfn_fn get_module_file; /* module-path channel, NULL when unresolved */
    xl_llx_fn load_library_ex;  /* altered-search loader, NULL when unresolved */
    /* ELF: load-relative VA of the phdr table to consult (the packed image's
     * e_phoff is a FILE offset into the appended PT_LOAD — using it as a
     * bias offset reads the inter-segment gap). 0 = fall back to e_phoff
     * (PE never sets it). */
    uint64_t phdr_va;
    /* Android/bionic anti-debug probe bitmap (plan WS-A §2.2.3). Pack-time
     * constant from xenolith_guard::android_probe_mask, encoded into the
     * aarch64 stub as a movz machine-code constant and stored here at
     * offset 128. PE and x86-64-ELF stubs write an explicit 0. Consumed
     * only on the aarch64 path as XL_PROBE_BIT_* (platform-local bits,
     * NOT global probe ids 17+). The trailing pad keeps sizeof at 136. */
    uint32_t probe_mask;
    uint32_t _pad2;
} XlHostCtx;

static void xl_copy(uint8_t *d, const uint8_t *s, uint32_t n) {
    uint32_t i;
    for (i = 0; i < n; i++) d[i] = s[i];
}

static void xl_zero(uint8_t *d, uint32_t n) {
    uint32_t i;
    for (i = 0; i < n; i++) d[i] = 0;
}

static uint32_t rd32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint16_t rd16(const uint8_t *p) {
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static uint64_t rd64(const uint8_t *p) {
    return (uint64_t)rd32(p) | ((uint64_t)rd32(p + 4) << 32);
}

static uint32_t rotl32(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

static void qr(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d) {
    *a += *b; *d ^= *a; *d = rotl32(*d, 16);
    *c += *d; *b ^= *c; *b = rotl32(*b, 12);
    *a += *b; *d ^= *a; *d = rotl32(*d, 8);
    *c += *d; *b ^= *c; *b = rotl32(*b, 7);
}

static void chacha20_block(const uint32_t key[8], uint32_t counter, const uint32_t nonce[3], uint8_t out[64]) {
    uint32_t x[16];
    uint32_t t[16];
    int i;
    x[0] = 0x61707865u; x[1] = 0x3320646eu; x[2] = 0x79622d32u; x[3] = 0x6b206574u;
    for (i = 0; i < 8; i++) x[4 + i] = key[i];
    x[12] = counter;
    x[13] = nonce[0]; x[14] = nonce[1]; x[15] = nonce[2];
    for (i = 0; i < 16; i++) t[i] = x[i];
    for (i = 0; i < 10; i++) {
        qr(&t[0], &t[4], &t[8], &t[12]);
        qr(&t[1], &t[5], &t[9], &t[13]);
        qr(&t[2], &t[6], &t[10], &t[14]);
        qr(&t[3], &t[7], &t[11], &t[15]);
        qr(&t[0], &t[5], &t[10], &t[15]);
        qr(&t[1], &t[6], &t[11], &t[12]);
        qr(&t[2], &t[7], &t[8], &t[13]);
        qr(&t[3], &t[4], &t[9], &t[14]);
    }
    for (i = 0; i < 16; i++) {
        uint32_t v = t[i] + x[i];
        out[i * 4 + 0] = (uint8_t)v;
        out[i * 4 + 1] = (uint8_t)(v >> 8);
        out[i * 4 + 2] = (uint8_t)(v >> 16);
        out[i * 4 + 3] = (uint8_t)(v >> 24);
    }
}

static void chacha20_xor(const uint32_t key[8], uint32_t counter, const uint32_t nonce[3],
                         const uint8_t *in, uint8_t *out, uint32_t len) {
    uint8_t block[64];
    uint32_t off = 0;
    while (off < len) {
        uint32_t n, i;
        chacha20_block(key, counter, nonce, block);
        counter++;
        n = len - off;
        if (n > 64) n = 64;
        for (i = 0; i < n; i++) out[off + i] = in[off + i] ^ block[i];
        off += n;
    }
}

/* Poly1305: 5x26-bit limbs. */
static uint32_t lt26(uint64_t v) { return (uint32_t)(v & 0x3ffffffu); }

static void poly1305_blocks(uint32_t h[5], const uint32_t r[5], const uint8_t *m, uint32_t len, int final_flag) {
    uint32_t s1 = r[1] * 5, s2 = r[2] * 5, s3 = r[3] * 5, s4 = r[4] * 5;
    while (len >= 16 || (final_flag && len > 0)) {
        uint32_t n[5];
        uint64_t d0, d1, d2, d3, d4;
        uint64_t c;
        uint8_t tmp[16];
        const uint8_t *p = m;
        uint32_t i;
        if (len < 16) {
            for (i = 0; i < 16; i++) tmp[i] = 0;
            for (i = 0; i < len; i++) tmp[i] = m[i];
            tmp[len] = 1;
            p = tmp;
            len = 0;
            final_flag = 2;
        } else {
            len -= 16;
            m += 16;
        }
        n[0] = rd32(p) & 0x3ffffffu;
        n[1] = (rd32(p + 3) >> 2) & 0x3ffffffu;
        n[2] = (rd32(p + 6) >> 4) & 0x3ffffffu;
        n[3] = (rd32(p + 9) >> 6) & 0x3ffffffu;
        n[4] = (rd32(p + 12) >> 8);
        if (final_flag != 2) n[4] |= 1u << 24;
        h[0] += n[0]; h[1] += n[1]; h[2] += n[2]; h[3] += n[3]; h[4] += n[4];
        d0 = (uint64_t)h[0]*r[0] + (uint64_t)h[1]*s4 + (uint64_t)h[2]*s3 + (uint64_t)h[3]*s2 + (uint64_t)h[4]*s1;
        d1 = (uint64_t)h[0]*r[1] + (uint64_t)h[1]*r[0] + (uint64_t)h[2]*s4 + (uint64_t)h[3]*s3 + (uint64_t)h[4]*s2;
        d2 = (uint64_t)h[0]*r[2] + (uint64_t)h[1]*r[1] + (uint64_t)h[2]*r[0] + (uint64_t)h[3]*s4 + (uint64_t)h[4]*s3;
        d3 = (uint64_t)h[0]*r[3] + (uint64_t)h[1]*r[2] + (uint64_t)h[2]*r[1] + (uint64_t)h[3]*r[0] + (uint64_t)h[4]*s4;
        d4 = (uint64_t)h[0]*r[4] + (uint64_t)h[1]*r[3] + (uint64_t)h[2]*r[2] + (uint64_t)h[3]*r[1] + (uint64_t)h[4]*r[0];
        c = d0 >> 26; h[0] = lt26(d0); d1 += c;
        c = d1 >> 26; h[1] = lt26(d1); d2 += c;
        c = d2 >> 26; h[2] = lt26(d2); d3 += c;
        c = d3 >> 26; h[3] = lt26(d3); d4 += c;
        c = d4 >> 26; h[4] = lt26(d4);
        h[0] += (uint32_t)c * 5;
        c = h[0] >> 26; h[0] = lt26(h[0]); h[1] += (uint32_t)c;
        if (final_flag == 2) break;
    }
}

static void wr32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static void poly1305_finish(uint32_t h[5], const uint32_t pad[4], uint8_t tag[16]) {
    uint32_t g0, g1, g2, g3, g4, c, mask;
    uint64_t f;
    uint32_t t0, t1, t2, t3;
    c = h[0] >> 26; h[0] &= 0x3ffffffu; h[1] += c;
    c = h[1] >> 26; h[1] &= 0x3ffffffu; h[2] += c;
    c = h[2] >> 26; h[2] &= 0x3ffffffu; h[3] += c;
    c = h[3] >> 26; h[3] &= 0x3ffffffu; h[4] += c;
    c = h[4] >> 26; h[4] &= 0x3ffffffu; h[0] += c * 5;
    c = h[0] >> 26; h[0] &= 0x3ffffffu; h[1] += c;
    g0 = h[0] + 5; c = g0 >> 26; g0 &= 0x3ffffffu;
    g1 = h[1] + c; c = g1 >> 26; g1 &= 0x3ffffffu;
    g2 = h[2] + c; c = g2 >> 26; g2 &= 0x3ffffffu;
    g3 = h[3] + c; c = g3 >> 26; g3 &= 0x3ffffffu;
    g4 = h[4] + c - (1u << 26);
    mask = (g4 >> 31) - 1u;
    g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
    mask = ~mask;
    h[0] = (h[0] & mask) | g0;
    h[1] = (h[1] & mask) | g1;
    h[2] = (h[2] & mask) | g2;
    h[3] = (h[3] & mask) | g3;
    h[4] = (h[4] & mask) | g4;
    t0 = ((h[0]      ) | (h[1] << 26)) & 0xffffffffu;
    t1 = ((h[1] >>  6) | (h[2] << 20)) & 0xffffffffu;
    t2 = ((h[2] >> 12) | (h[3] << 14)) & 0xffffffffu;
    t3 = ((h[3] >> 18) | (h[4] <<  8)) & 0xffffffffu;
    f = (uint64_t)t0 + pad[0]; t0 = (uint32_t)f;
    f = (uint64_t)t1 + pad[1] + (f >> 32); t1 = (uint32_t)f;
    f = (uint64_t)t2 + pad[2] + (f >> 32); t2 = (uint32_t)f;
    f = (uint64_t)t3 + pad[3] + (f >> 32); t3 = (uint32_t)f;
    wr32(tag, t0);
    wr32(tag + 4, t1);
    wr32(tag + 8, t2);
    wr32(tag + 12, t3);
}


static void aead_seal(const uint8_t key[32], const uint8_t nonce12[12], const uint8_t *aad, uint32_t aad_len,
                      const uint8_t *pt, uint32_t pt_len, uint8_t *ct_out, uint8_t tag[16]) {
    uint32_t k[8], n[3];
    uint8_t otk[64];
    uint32_t r[5], pad[4], h[5];
    int i;
    for (i = 0; i < 8; i++) k[i] = rd32(key + i * 4);
    n[0] = rd32(nonce12); n[1] = rd32(nonce12 + 4); n[2] = rd32(nonce12 + 8);
    chacha20_block(k, 0, n, otk);
    r[0] = rd32(otk) & 0x3ffffffu;
    r[1] = (rd32(otk + 3) >> 2) & 0x3ffff03u;
    r[2] = (rd32(otk + 6) >> 4) & 0x3ffc0ffu;
    r[3] = (rd32(otk + 9) >> 6) & 0x3f03fffu;
    r[4] = (rd32(otk + 12) >> 8) & 0x00fffffu;
    pad[0] = rd32(otk + 16); pad[1] = rd32(otk + 20); pad[2] = rd32(otk + 24); pad[3] = rd32(otk + 28);
    for (i = 0; i < 5; i++) h[i] = 0;
    /* Produce the ciphertext first: Poly1305 authenticates the CIPHERTEXT
     * (aad || ct || lens), matching the pack-side seal and aead_open. MACing
     * the plaintext made every deterministic re-seal mismatch the tag. */
    chacha20_xor(k, 1, n, pt, ct_out, pt_len);
    if (aad_len) {
        uint32_t full = aad_len & ~15u;
        if (full) poly1305_blocks(h, r, aad, full, 0);
        if (aad_len != full) {
            uint8_t z[16];
            xl_zero(z, 16);
            xl_copy(z, aad + full, aad_len - full);
            poly1305_blocks(h, r, z, 16, 0);
        }
    }
    if (pt_len) {
        uint32_t full = pt_len & ~15u;
        if (full) poly1305_blocks(h, r, ct_out, full, 0);
        if (pt_len != full) {
            uint8_t z[16];
            xl_zero(z, 16);
            xl_copy(z, ct_out + full, pt_len - full);
            poly1305_blocks(h, r, z, 16, 0);
        }
    }
    {
        uint8_t lens[16];
        xl_zero(lens, 16);
        lens[0] = (uint8_t)aad_len; lens[1] = (uint8_t)(aad_len >> 8); lens[2] = (uint8_t)(aad_len >> 16); lens[3] = (uint8_t)(aad_len >> 24);
        lens[8] = (uint8_t)pt_len; lens[9] = (uint8_t)(pt_len >> 8); lens[10] = (uint8_t)(pt_len >> 16); lens[11] = (uint8_t)(pt_len >> 24);
        poly1305_blocks(h, r, lens, 16, 1);
    }
    poly1305_finish(h, pad, tag);
}

static int ct_eq16(const uint8_t *a, const uint8_t *b) {
    uint8_t x = 0;
    int i;
    for (i = 0; i < 16; i++) x |= a[i] ^ b[i];
    return x == 0;
}

static int aead_open(const uint8_t key[32], const uint8_t nonce12[12], const uint8_t *aad, uint32_t aad_len,
                     const uint8_t *ct, uint32_t ct_len, const uint8_t tag[16], uint8_t *out) {
    uint32_t k[8], n[3];
    uint8_t otk[64];
    uint32_t r[5], pad[4], h[5];
    uint8_t got[16];
    uint8_t lens[16];
    int i;
    for (i = 0; i < 8; i++) k[i] = rd32(key + i * 4);
    n[0] = rd32(nonce12); n[1] = rd32(nonce12 + 4); n[2] = rd32(nonce12 + 8);
    chacha20_block(k, 0, n, otk);
    r[0] = rd32(otk) & 0x3ffffffu;
    r[1] = (rd32(otk + 3) >> 2) & 0x3ffff03u;
    r[2] = (rd32(otk + 6) >> 4) & 0x3ffc0ffu;
    r[3] = (rd32(otk + 9) >> 6) & 0x3f03fffu;
    r[4] = (rd32(otk + 12) >> 8) & 0x00fffffu;
    pad[0] = rd32(otk + 16); pad[1] = rd32(otk + 20); pad[2] = rd32(otk + 24); pad[3] = rd32(otk + 28);
    for (i = 0; i < 5; i++) h[i] = 0;
    if (aad_len) {
        uint32_t full = aad_len & ~15u;
        if (full) poly1305_blocks(h, r, aad, full, 0);
        if (aad_len != full) {
            uint8_t z[16];
            xl_zero(z, 16);
            xl_copy(z, aad + full, aad_len - full);
            poly1305_blocks(h, r, z, 16, 0);
        }
    }
    if (ct_len) {
        uint32_t full = ct_len & ~15u;
        if (full) poly1305_blocks(h, r, ct, full, 0);
        if (ct_len != full) {
            uint8_t z[16];
            xl_zero(z, 16);
            xl_copy(z, ct + full, ct_len - full);
            poly1305_blocks(h, r, z, 16, 0);
        }
    }
    xl_zero(lens, 16);
    lens[0] = (uint8_t)aad_len; lens[1] = (uint8_t)(aad_len >> 8); lens[2] = (uint8_t)(aad_len >> 16); lens[3] = (uint8_t)(aad_len >> 24);
    lens[8] = (uint8_t)ct_len; lens[9] = (uint8_t)(ct_len >> 8); lens[10] = (uint8_t)(ct_len >> 16); lens[11] = (uint8_t)(ct_len >> 24);
    poly1305_blocks(h, r, lens, 16, 1);
    poly1305_finish(h, pad, got);
    if (!ct_eq16(got, tag)) return 0;
    chacha20_xor(k, 1, n, ct, out, ct_len);
    return 1;
}

static uint32_t mul_inv_odd(uint32_t v) {
    uint32_t x = v;
    x *= 2u - v * x;
    x *= 2u - v * x;
    x *= 2u - v * x;
    x *= 2u - v * x;
    return x;
}

static int reconstruct_mba(const uint8_t mba[96], uint8_t secret[32]) {
    int i;
    for (i = 0; i < 8; i++) {
        uint32_t mul = rd32(mba + i * 12);
        uint32_t add = rd32(mba + i * 12 + 4);
        uint32_t xor_mask = rd32(mba + i * 12 + 8);
        uint32_t word;
        if ((mul & 1u) == 0) return 0;
        word = (xor_mask - add) * mul_inv_odd(mul);
        secret[i * 4 + 0] = (uint8_t)word;
        secret[i * 4 + 1] = (uint8_t)(word >> 8);
        secret[i * 4 + 2] = (uint8_t)(word >> 16);
        secret[i * 4 + 3] = (uint8_t)(word >> 24);
    }
    return 1;
}

static void mix_key(const uint8_t secret[32], const uint8_t meas[32], uint8_t out[32]) {
    uint8_t wrap[16];
    int i;
    wrap[0] = 0x4e; wrap[1] = 0x53; wrap[2] = 0x70; wrap[3] = 0x6b;
    wrap[4] = 0x76; wrap[5] = 0x32; wrap[6] = 0x00; wrap[7] = 0x7f;
    wrap[8] = 0xa1; wrap[9] = 0x3c; wrap[10] = 0x91; wrap[11] = 0x08;
    wrap[12] = 0x55; wrap[13] = 0xd2; wrap[14] = 0xee; wrap[15] = 0x11;
    for (i = 0; i < 32; i++) out[i] = (uint8_t)(secret[i] ^ meas[i] ^ wrap[i % 16]);
}

static int vp(XlHostCtx *ctx, void *addr, uint64_t size, uint32_t neu, uint32_t *old) {
    if (!ctx->vprotect) return 0;
    return ctx->vprotect(addr, size, neu, old) != 0;
}

/* Final protection for a decrypted region, derived from the image's own
 * headers — NOT from the `old` value reported by vp().
 *
 * Why not `old`: (1) on Windows, a region woken from our own sealed state
 * reports PAGE_NOACCESS, and restoring that re-seals the page into an
 * infinite fault loop; (2) the ELF mprotect shim cannot know the previous
 * protection and echoes the REQUESTED constant back through *old, so an
 * RW-window open followed by restore-old would leave text non-executable.
 * Deriving from the section table is faithful on both hosts and preserves
 * legitimately writable-executable sections (MinGW/Cygwin RWX .text,
 * self-patching code): forcing RX there crashes the unpacked image on its
 * first self-write. Ordinary RX .text still ends as RX. Only sealed regions
 * (always executable sections) pass through here, so the result is always
 * XL_PAGE_RX or XL_PAGE_RWX on well-formed inputs; RX is the fallback. */
static uint32_t xl_final_protect(XlHostCtx *ctx, uint32_t rva) {
    const uint8_t *b = ctx->image_base;
    uint32_t i;
    if (b[0] == 'M' && b[1] == 'Z') {
        uint32_t lf = rd32(b + 0x3C);
        uint32_t nsec, span;
        const uint8_t *tbl, *s;
        uint32_t vs, va, rs, ch;
        if (lf < 0x40 || lf + 24 > 0x40000) return XL_PAGE_RX;
        if (b[lf] != 'P' || b[lf + 1] != 'E') return XL_PAGE_RX;
        nsec = rd16(b + lf + 6);
        tbl = b + lf + 24 + rd16(b + lf + 20);
        if (nsec > 96) nsec = 96;
        for (i = 0; i < nsec; i++) {
            s = tbl + i * 40;
            vs = rd32(s + 8); va = rd32(s + 12); rs = rd32(s + 16); ch = rd32(s + 36);
            span = vs > rs ? vs : rs;
            if (rva >= va && rva - va < span) {
                if ((ch & 0x20000000u) && (ch & 0x80000000u)) return XL_PAGE_RWX;
                if (ch & 0x20000000u) return XL_PAGE_RX;
                if (ch & 0x80000000u) return XL_PAGE_RW;
                return 0x02u; /* PAGE_READONLY */
            }
        }
        return XL_PAGE_RX;
    }
    if (b[0] == 0x7f && b[1] == 'E' && b[2] == 'L' && b[3] == 'F') {
        /* Packed ELFs: e_phoff is a file offset whose bias-relative address
         * lands in the appended PT_LOAD only by accident — the stub hands us
         * the real table VA in ctx->phdr_va. Unpacked inputs (e.g. PE-path
         * leftovers, host emulators) keep the e_phoff fallback. */
        uint64_t phoff = ctx->phdr_va ? ctx->phdr_va : rd64(b + 0x20);
        uint16_t phentsize = rd16(b + 0x36), phnum = rd16(b + 0x38);
        const uint8_t *ph;
        if (phentsize < 56 || phnum > 64) return XL_PAGE_RX;
        if (phoff == 0 || phoff + (uint64_t)phnum * phentsize > 0x40000000u) return XL_PAGE_RX;
        for (i = 0; i < phnum; i++) {
            ph = b + phoff + (uint64_t)i * phentsize;
            if (rd32(ph) != 1) continue; /* PT_LOAD */
            {
                uint64_t vaddr = rd64(ph + 0x10), memsz = rd64(ph + 0x28);
                uint32_t fl = rd32(ph + 4);
                if ((uint64_t)rva >= vaddr && (uint64_t)rva - vaddr < memsz) {
                    if ((fl & 0x1u) && (fl & 0x2u)) return XL_PAGE_RWX; /* PF_X|PF_W */
                    if (fl & 0x1u) return XL_PAGE_RX;
                    if (fl & 0x2u) return XL_PAGE_RW;
                    return 0x02u;
                }
            }
        }
        return XL_PAGE_RX;
    }
    return XL_PAGE_RX;
}


static int copy_rx(XlHostCtx *ctx, uint8_t *dst, const uint8_t *src, uint32_t n, uint32_t final_prot) {
    uint32_t old = 0;
    uint32_t rva = (uint32_t)(dst - ctx->image_base);
    if (n == 0) return 1;
    if (!vp(ctx, dst, n, XL_PAGE_RW, &old)) return 0;
    xl_copy(dst, src, n);
    /* `final_prot` is only the fallback when the rva does not resolve to a
     * section/segment; otherwise the destination returns to the protection
     * its own header declares (see xl_final_protect). */
    if (!vp(ctx, dst, n, rva ? xl_final_protect(ctx, rva) : final_prot, &old)) return 0;
    return 1;
}

/* TASK-024: AAD for a sealed import record. Mirrors
 * xenolith_protocol::import_aad byte-for-byte. */
static void import_aad(uint8_t aad[32], uint8_t platform, uint32_t flags,
                       uint32_t iat_rva, uint32_t name_len, uint32_t dll_len,
                       uint32_t index) {
    xl_zero(aad, 32);
    aad[0] = 'X'; aad[1] = 'L'; aad[2] = 'V'; aad[3] = '2';
    aad[4] = 2; aad[5] = 0;
    aad[6] = 'I';
    aad[7] = platform;
    aad[8] = (uint8_t)flags; aad[9] = (uint8_t)(flags >> 8); aad[10] = (uint8_t)(flags >> 16); aad[11] = (uint8_t)(flags >> 24);
    aad[12] = (uint8_t)iat_rva; aad[13] = (uint8_t)(iat_rva >> 8); aad[14] = (uint8_t)(iat_rva >> 16); aad[15] = (uint8_t)(iat_rva >> 24);
    aad[16] = (uint8_t)name_len; aad[17] = (uint8_t)(name_len >> 8);
    aad[18] = (uint8_t)dll_len; aad[19] = (uint8_t)(dll_len >> 8);
    aad[20] = (uint8_t)index; aad[21] = (uint8_t)(index >> 8); aad[22] = (uint8_t)(index >> 16); aad[23] = (uint8_t)(index >> 24);
}

/* AAD for a sealed page region. reloc_bytes MUST mirror the host
 * (xenolith_protocol::region_aad): the packer authenticates the reloc-table
 * byte length in the tail dword. Mismatching it made every AEAD open fail
 * for images whose envelope carries at least one reloc record (the silent
 * ASLR boot failure — envelope seals with relocs*8, an older core opened
 * with 0). Callers pass the value parsed from the same envelope. */
static void region_aad(uint8_t aad[32], uint8_t platform, uint8_t profile, uint32_t flags,
                       uint32_t index, uint32_t rva, uint32_t len, uint32_t policy,
                       uint32_t reloc_bytes) {
    xl_zero(aad, 32);
    aad[0] = 'X'; aad[1] = 'L'; aad[2] = 'V'; aad[3] = '2';
    aad[4] = 2; aad[5] = 0;
    aad[6] = platform;
    aad[7] = profile;
    aad[8] = (uint8_t)flags; aad[9] = (uint8_t)(flags >> 8); aad[10] = (uint8_t)(flags >> 16); aad[11] = (uint8_t)(flags >> 24);
    aad[12] = (uint8_t)index; aad[13] = (uint8_t)(index >> 8); aad[14] = (uint8_t)(index >> 16); aad[15] = (uint8_t)(index >> 24);
    aad[16] = (uint8_t)rva; aad[17] = (uint8_t)(rva >> 8); aad[18] = (uint8_t)(rva >> 16); aad[19] = (uint8_t)(rva >> 24);
    aad[20] = (uint8_t)len; aad[21] = (uint8_t)(len >> 8); aad[22] = (uint8_t)(len >> 16); aad[23] = (uint8_t)(len >> 24);
    aad[24] = (uint8_t)policy; aad[25] = (uint8_t)(policy >> 8); aad[26] = (uint8_t)(policy >> 16); aad[27] = (uint8_t)(policy >> 24);
    aad[28] = (uint8_t)reloc_bytes; aad[29] = (uint8_t)(reloc_bytes >> 8);
    aad[30] = (uint8_t)(reloc_bytes >> 16); aad[31] = (uint8_t)(reloc_bytes >> 24);
}

/* Reloc-table byte length as the packer puts it in the region AAD tail
 * (reloc count * 8), and — before any page is decrypted — the ASLR delta
 * recovered from the loader's own fixups.
 *
 * The in-memory OptionalHeader.ImageBase CANNOT serve as the preferred base:
 * the loader rewrites that very field to the actual base while relocating
 * (measured: a stock ASLR xz.exe shows ImageBase == actual at its entry
 * breakpoint). Deriving delta from it yields 0, and every DIR64 slot on a
 * decrypted page then stays UNRELOCATED — the silent delta!=0 crash.
 *
 * The delta instead comes from the packer's own disk invariant: every
 * protected page body is filled with 0xCC, and the loader applies each
 * recorded fixup to those bytes BEFORE the stub decrypts. A recorded slot
 * read now holds 0xCCCCCCCCCCCCCCCC + delta (wrapping); all recorded slots
 * must agree on one delta, otherwise the envelope does not describe this
 * image and boot fails closed. With no records there is nothing to fix up
 * and delta stays 0. */
static int xl_reloc_scan(const uint8_t *env, uint32_t env_len,
                         const uint8_t *image_base, int read_delta,
                         uint32_t *reloc_bytes_out, uint64_t *delta_out) {
    uint32_t region_count, cur, i;
    uint64_t delta = 0;
    int have_delta = 0;
    if (env_len < 16 + 96 + 16 + 16 + 8 + 2) return 0;
    region_count = rd32(env + 12);
    /* Walk-only: no 64-slot state table here, so the count is bounded by the
     * envelope length checks inside the loop, not by XlRegionTable's size.
     * (A 64 cap here failed every image with more than 64 pages — openssl,
     * cargo.) */
    if (region_count > 0xffffu) return 0;
    cur = 16;
    cur += 96;                 /* mba */
    cur += 16;                 /* opcode seed */
    cur += 16;                 /* api salt */
    cur += 8;                  /* opcode map */
    cur += 2 + rd16(env + cur); /* stolen */
    cur += 4;                  /* program length */
    if (cur > env_len) return 0;
    cur += rd32(env + cur - 4); /* program bytes */
    cur += 4;                  /* policy */
    for (i = 0; i < region_count; i++) {
        uint32_t ct_len;
        if (cur + 4 + 4 + 4 + 12 + 4 > env_len) return 0;
        cur += 4 + 4 + 4 + 12;
        ct_len = rd32(env + cur); cur += 4;
        if (ct_len > XL_MAX_REGION || cur + ct_len + 16 > env_len) return 0;
        cur += ct_len + 16;
    }
    if (cur + 4 > env_len) return 0;
    {
        uint32_t n = rd32(env + cur); cur += 4;
        uint32_t imp_sealed = rd32(env + 8) & 0x2u;
        if (n > 0xffffu) return 0;
        for (i = 0; i < n; i++) {
            uint32_t name_len, dll_len, payload;
            if (cur + 32 + 4 + 2 + 2 > env_len) return 0;
            cur += 32 + 4;
            name_len = rd16(env + cur); cur += 2;
            dll_len = rd16(env + cur); cur += 2;
            payload = name_len + dll_len;
            if (imp_sealed) payload += 12 + 16;
            if (cur + payload > env_len) return 0;
            cur += payload;
        }
    }
    if (cur + 4 > env_len) return 0;
    {
        /* skip the keep list */
        uint32_t n = rd32(env + cur); cur += 4;
        if (n > 0xffffu || cur + n * 4 > env_len) return 0;
        cur += n * 4;
    }
    if (cur + 4 > env_len) return 0;
    {
        uint32_t n = rd32(env + cur); cur += 4;
        if (n > 0xffffu || cur + n * 8 > env_len) return 0;
        *reloc_bytes_out = n * 8u;
        for (i = 0; i < n; i++) {
            uint32_t rva = rd32(env + cur + i * 8);
            uint16_t kind = rd16(env + cur + i * 8 + 4);
            if (read_delta && kind == 10) {
                uint64_t v = 0;
                int k;
                for (k = 0; k < 8; k++)
                    v |= ((uint64_t)image_base[rva + k]) << (8 * k);
                v -= 0xCCCCCCCCCCCCCCCCull; /* disk filler + delta */
                if (have_delta && v != delta) return 0;
                delta = v;
                have_delta = 1;
            }
        }
        cur += n * 8;
    }
    *delta_out = delta;
    return 1;
}

/* The in-memory OptionalHeader.ImageBase is NOT usable as the preferred
 * base (the loader rewrites it to the actual base while relocating), so
 * no PE header parse survives here — delta comes from xl_reloc_scan. */

/* Re-apply the loader's DIR64 fixups to slots inside decrypted pages.
 * `delta` arrives from xl_reloc_scan (computed BEFORE decryption, from the
 * loader-fixed 0xCC page filler) — the in-memory ImageBase field is already
 * the actual base at this point, so it cannot yield the delta. */
static int apply_dir64(XlHostCtx *ctx, const uint8_t *env, uint32_t env_len, uint32_t *curp,
                       uint64_t delta) {
    uint32_t cur = *curp;
    uint32_t n, i;
    if (cur + 4 > env_len) return 0;
    n = rd32(env + cur);
    cur += 4;
    for (i = 0; i < n; i++) {
        uint32_t rva;
        uint16_t kind;
        if (cur + 8 > env_len) return 0;
        rva = rd32(env + cur);
        cur += 4;
        kind = rd16(env + cur);
        cur += 4;
        if (kind == 10 && delta != 0) {
            uint8_t *p = ctx->image_base + rva;
            uint32_t old = 0;
            uint64_t v = 0;
            int k;
            if (!vp(ctx, p, 8, XL_PAGE_RW, &old)) return 0;
            for (k = 0; k < 8; k++) v |= ((uint64_t)p[k]) << (8 * k);
            v += delta;
            for (k = 0; k < 8; k++) p[k] = (uint8_t)(v >> (8 * k));
            if (!vp(ctx, p, 8, old ? old : XL_PAGE_RX, &old)) return 0;
        }
    }
    *curp = cur;
    return 1;
}


/* ---- G5/TASK-026: region lifecycle -------------------------------------
 * Dormant regions stay SEALED (PAGE_NOACCESS, ciphertext in place) after
 * bootstrap. The fault entry decrypts on first execution; quiesce re-seals
 * every region that is provably quiescent (refcount 0 and no qword on the
 * current stack pointing into it). The seal is a deterministic replay of
 * the original AEAD record (same key/nonce/AAD), so no tag storage needed.
 */

#define XL_REGION_LIVE 0u
#define XL_REGION_SEALED 1u

typedef struct XlRegionState {
    uint32_t rva;
    uint32_t len;
    uint32_t index;
    uint32_t rec_off;
    uint8_t state;
    uint8_t lazy;
    uint16_t refcount;
} XlRegionState;

typedef struct XlRegionTable {
    XlRegionState st[64];
    uint32_t count;
    /* Reloc-table byte length for the region AAD tail (must match the
     * packer's xenolith_protocol::region_aad). */
    uint32_t reloc_bytes;
    uint8_t secret[32];
    uint8_t runtime[32];
    uint8_t ok;
} XlRegionTable;

/* The runtime state lives in an INITIALIZED data section so the injected
 * image carries its bytes (zero) inline - .bss would need separate
 * allocation, which the stub cannot do. rstate persists the per-region
 * seal state across fault/quiesce calls: each call rebuilds the static
 * table from the envelope, which resets every state to LIVE. */
typedef struct XlGState {
    XlHostCtx ctx;
    uint32_t ok;
    uint32_t pad;
    uint32_t rcount;
    uint8_t rstate[64];
    /* Fault-path breadcrumbs (G5 bring-up): [0] entries, [1] last code,
     * [2] last verdict (1=search/2=opened/3=build-fail/4=overlay-fail/
     * 5=open-fail), [3] last fault RVA. */
    uint32_t dbg[4];
    /* TASK-027: thread-exit quiesce runs concurrently with process-detach
     * quiesce. Racing seals write identical bytes, but the key zeroize must
     * never interleave with a seal that still needs the key. */
    volatile long quiescing;
} XlGState;

#if defined(_MSC_VER)
#pragma data_seg(".xlg")
#else
/* GCC/clang: same section, same "must be PROGBITS" contract. Without the
 * attribute the state lands in .data and runtime_image cannot split it. */
__attribute__((section(".xlg"), used))
#endif
/* Nonzero pad forces an INITIALIZED section: a zero initializer would land
 * in .bss, whose bytes the injected image cannot carry. */
static XlGState g_xl = { {0}, 0u, 0x4E35u, 0u, {0}, {0} };

/* Module-directory-first import resolution.
 *
 * The OS loader resolves a module's DEPENDENCIES starting from that
 * module's own directory (and LoadLibraryExW(...,
 * LOAD_WITH_ALTERED_SEARCH_PATH) pins the same start directory for the
 * loaded file). The stub's bare LoadLibraryA instead searches the HOST
 * EXE's application directory first, so sibling DLLs that ship next to
 * the packed module were invisible during the writeback binding and the
 * FIRST such import failed the whole load (DllMain-false -> loader exit
 * ERROR_DLL_INIT_FAILED) even though the original loaded fine in place
 * (observed: libclang-cpp.dll + libLLVM-19/libstdc++-6/... siblings).
 * Resolve "<module dir>\<dep>" through LoadLibraryExA with the altered
 * search flag to mirror the loader; the bare-name call stays as the
 * fallback for when the channel is unavailable. State machine in
 * g_xl_moddir[0]: 2 = not resolved yet, 0 = failed, else first char of
 * the directory (with trailing separator, NUL-terminated). Touched only
 * under the loader lock during DLL_PROCESS_ATTACH. */
/* Resolve the packed module's own directory into `buf` (stack): returns
 * the directory length INCLUDING the trailing separator, 0 when the
 * channel is unavailable or the path does not fit. Stack-only by design:
 * the .xlg state page is not writable until the G5 publish, which runs
 * AFTER import binding. */
static uint32_t xl_module_dir(XlHostCtx *ctx, char *buf, uint32_t cap) {
    uint32_t n, i;
    if (!ctx || !ctx->get_module_file || cap < 8) return 0;
    n = ctx->get_module_file(ctx->image_base, buf, cap - 1);
    if (n == 0 || n >= cap - 1) return 0;
    i = n;
    while (i > 0 && buf[i - 1] != 0x5C /* backslash */ && buf[i - 1] != '/') i--;
    if (i == 0) return 0;
    buf[i] = 0;
    return i;
}
#if defined(_MSC_VER)
#pragma data_seg()
#endif


/* Offset of the envelope policy u32 (after stolen+program). */
static uint32_t xl_policy_off(const uint8_t *env) {
    uint32_t cur = 16 + 96 + 16 + 16 + 8; /* prefix+mba+seed+salt+map */
    uint32_t stolen_len = rd16(env + cur);
    cur += 2 + stolen_len;
    cur += 4;                              /* program length */
    cur += rd32(env + cur - 4);            /* program bytes */
    return cur;                            /* policy u32 lives here */
}

#if defined(__aarch64__)
/* ---- Android/bionic anti-debug probes (plan WS-A §2.2.2) ---------------
 * Compiled only into the NDK-built aarch64 core. The host/CI x86-64 core
 * is MSVC/gcc-built (no inline svc wrappers there; see the architecture
 * scoping decision in plan §2.2.2) and this whole block is preprocessed
 * out. Everything below is:
 *   - freestanding: raw Linux aarch64 syscalls (svc #0), no libc, no new
 *     host-API surface through XlHostCtx;
 *   - stateless: no statics, no globals, no .xlg writes — every activation
 *     runs from zero (review 3-1), so a dlopen/dlclose soak never depends
 *     on storage that a remap would reset;
 *   - stack-only: paths/markers are built byte-wise (the core contract
 *     forbids string literals and static storage).
 * Probe bits are PLATFORM-LOCAL (bit i = android_probes()[i] on the pack
 * side), deliberately not the global probe ids 17+: ids ≥17 cannot fit a
 * single stub movz imm16 (review 3-3).
 */
#define XL_PROBE_BIT_TRACERPID   0x1u
#define XL_PROBE_BIT_PTRACE_SELF 0x2u
#define XL_PROBE_BIT_MAPS        0x4u

/* aarch64 generic syscall numbers (asm-generic/unistd.h). */
#define XL_SYS_OPENAT   56
#define XL_SYS_CLOSE    57
#define XL_SYS_READ     63
#define XL_SYS_PTRACE  117
#define XL_SYS_GETPPID 172

/* Raw 3-arg syscall. Linux aarch64 returns -errno (negative long) on
 * failure; only x0 is clobbered. musl-style register bindings. */
static long xl_sys3(long nr, long a, long b, long c) {
    register long x8 __asm__("x8") = nr;
    register long x0 __asm__("x0") = a;
    register long x1 __asm__("x1") = b;
    register long x2 __asm__("x2") = c;
    __asm__ __volatile__ ("svc #0"
                          : "=r"(x0)
                          : "r"(x8), "0"(x0), "r"(x1), "r"(x2)
                          : "memory", "cc");
    return x0;
}

static long xl_open_readonly(const char *path) {
    /* openat(AT_FDCWD, path, O_RDONLY) */
    return xl_sys3(XL_SYS_OPENAT, -100L, (long)(uintptr_t)path, 0L);
}

/* Three-way TracerPid verdict — mirrors xenolith_guard::classify_tracerpid
 * (the Rust reference semantics; this copy is the one that executes).
 * Review 3-2: shared by both Tracer probes so the self-attach residue
 * (TracerPid == getppid()) never cross-fires. */
#define XL_TRACER_NONE       0
#define XL_TRACER_BENIGN_SELF 1
#define XL_TRACER_HIT        2

static int xl_classify_tracerpid(uint32_t tracer_pid, uint32_t ppid) {
    if (tracer_pid == 0) return XL_TRACER_NONE;
    if (tracer_pid == ppid) return XL_TRACER_BENIGN_SELF;
    return XL_TRACER_HIT;
}

/* Parse the TracerPid value out of /proc/self/status. Returns 1 and sets
 * *out on success; 0 when the file cannot be read far enough to contain a
 * parseable TracerPid line (fail closed — the caller treats 0 as a
 * refusal). The status blob sits well inside 4 KiB on every Android
 * release to date; reads accumulate into one buffer until EOF or full. */
static int xl_read_status_tracer_pid(uint32_t *out) {
    char path[18];
    uint8_t buf[4096];
    long fd, n;
    uint32_t have = 0, i;
    /* "/proc/self/status" is 17 chars + NUL: the buffer is 18 so openat
     * gets a terminated C string (no over-read into stack garbage). */
    path[0]='/'; path[1]='p'; path[2]='r'; path[3]='o'; path[4]='c';
    path[5]='/'; path[6]='s'; path[7]='e'; path[8]='l'; path[9]='f';
    path[10]='/'; path[11]='s'; path[12]='t'; path[13]='a'; path[14]='t';
    path[15]='u'; path[16]='s'; path[17]=0;
    fd = xl_open_readonly(path);
    if (fd < 0) return 0;
    while (have < sizeof(buf)) {
        n = xl_sys3(XL_SYS_READ, fd, (long)(uintptr_t)&buf[have],
                    (long)(sizeof(buf) - have));
        if (n < 0) { xl_sys3(XL_SYS_CLOSE, fd, 0, 0); return 0; }
        if (n == 0) break;
        have += (uint32_t)n;
    }
    xl_sys3(XL_SYS_CLOSE, fd, 0, 0);
    /* Find "TracerPid:" then the following decimal. Bounded by have-1 so
     * the k+10 lookahead never reads uninitialized stack bytes. */
    for (i = 0; i + 10 < have; i++) {
        if (buf[i]   == 'T' && buf[i+1] == 'r' && buf[i+2] == 'a' &&
            buf[i+3] == 'c' && buf[i+4] == 'e' && buf[i+5] == 'r' &&
            buf[i+6] == 'P' && buf[i+7] == 'i' && buf[i+8] == 'd' &&
            buf[i+9] == ':') {
            uint32_t k = i + 10, v = 0, digits = 0;
            while (k < have && (buf[k] == ' ' || buf[k] == '\t')) k++;
            while (k < have && buf[k] >= '0' && buf[k] <= '9') {
                v = v * 10u + (uint32_t)(buf[k] - '0');
                digits++;
                k++;
                if (digits > 10) return 0; /* refuse absurd values */
            }
            if (digits == 0) return 0;
            *out = v;
            return 1;
        }
    }
    return 0;
}

/* Case-insensitive ASCII lowercase. */
static uint8_t xl_lc(uint8_t c) {
    return (uint8_t)((c >= 'A' && c <= 'Z') ? c + 0x20 : c);
}

/* Scan /proc/self/maps for analysis-module markers. The needle table is
 * built byte-wise on the stack (the core contract forbids static storage
 * and string literals: .rodata would be dropped by the image extractor).
 * Reads flow through a window that carries the previous chunk's tail so
 * markers spanning a 4 KiB boundary still match. Total scan is capped at
 * 4 MiB (a maps blob that large is already pathological; the cap bounds
 * time under adversarial mapping storms). Returns 1 on a marker hit, 0 on
 * clean, -1 on unreadable maps (caller fails closed on nonzero). */
static int xl_maps_contains_marker(void) {
    char path[16];
    uint8_t mk[4][11];
    uint8_t mlen[4];
    uint8_t win[4096 + 16];
    long fd, n;
    uint32_t carry = 0, total = 0, w, m, k, i;
    /* "/proc/self/maps" is 15 chars + NUL. */
    path[0]='/'; path[1]='p'; path[2]='r'; path[3]='o'; path[4]='c';
    path[5]='/'; path[6]='s'; path[7]='e'; path[8]='l'; path[9]='f';
    path[10]='/'; path[11]='m'; path[12]='a'; path[13]='p'; path[14]='s';
    path[15]=0;
    /* "frida" */
    mk[0][0]='f'; mk[0][1]='r'; mk[0][2]='i'; mk[0][3]='d'; mk[0][4]='a';
    /* "xposed" */
    mk[1][0]='x'; mk[1][1]='p'; mk[1][2]='o'; mk[1][3]='s'; mk[1][4]='e';
    mk[1][5]='d';
    /* "substrate" */
    mk[2][0]='s'; mk[2][1]='u'; mk[2][2]='b'; mk[2][3]='s'; mk[2][4]='t';
    mk[2][5]='r'; mk[2][6]='a'; mk[2][7]='t'; mk[2][8]='e';
    /* "dlopen-hook" */
    mk[3][0]='d'; mk[3][1]='l'; mk[3][2]='o'; mk[3][3]='p'; mk[3][4]='e';
    mk[3][5]='n'; mk[3][6]='-'; mk[3][7]='h'; mk[3][8]='o'; mk[3][9]='o';
    mk[3][10]='k';
    mlen[0]=5; mlen[1]=6; mlen[2]=9; mlen[3]=11;
    fd = xl_open_readonly(path);
    if (fd < 0) return -1;
    for (;;) {
        n = xl_sys3(XL_SYS_READ, fd, (long)(uintptr_t)&win[carry],
                    (long)(sizeof(win) - carry));
        if (n < 0) { xl_sys3(XL_SYS_CLOSE, fd, 0, 0); return -1; }
        if (n == 0) break;
        total += (uint32_t)n;
        if (total > 4u * 1024u * 1024u) {
            xl_sys3(XL_SYS_CLOSE, fd, 0, 0);
            return -1; /* unbounded maps: treat as tamper, fail closed */
        }
        w = carry + (uint32_t)n;
        for (m = 0; m < 4; m++) {
            uint32_t last;
            if (w < mlen[m]) continue; /* short window: no full match fits */
            last = w - mlen[m];
            for (k = 0; k <= last; k++) {
                int hit = 1;
                for (i = 0; i < mlen[m]; i++) {
                    if (xl_lc(win[k + i]) != mk[m][i]) { hit = 0; break; }
                }
                if (hit) { xl_sys3(XL_SYS_CLOSE, fd, 0, 0); return 1; }
            }
        }
        /* Carry the max-marker-minus-1 tail into the next round. */
        carry = 10;
        if (w < carry) carry = w;
        for (k = 0; k < carry; k++) win[k] = win[w - carry + k];
    }
    xl_sys3(XL_SYS_CLOSE, fd, 0, 0);
    return 0;
}

/* Run the enabled probes. Returns 1 = proceed, 0 = fail closed (the
 * activation returns 0 and the image refuses to unpack — same contract as
 * the Windows stub's STAGE_DEBUGGER path). A zero mask means the packer
 * explicitly shipped no probes (only reachable by a deliberate custom
 * build; the packer's profile defaults always arm at least TracerPidScan)
 * and passes. */
static int xl_android_guard(uint32_t probe_mask) {
    uint32_t ppid, tp;
    if (probe_mask == 0) return 1;
    ppid = (uint32_t)xl_sys3(XL_SYS_GETPPID, 0, 0, 0);
    if (probe_mask & XL_PROBE_BIT_TRACERPID) {
        if (!xl_read_status_tracer_pid(&tp)) return 0;
        if (xl_classify_tracerpid(tp, ppid) == XL_TRACER_HIT) return 0;
    }
    if (probe_mask & XL_PROBE_BIT_PTRACE_SELF) {
        /* CUSTOM BUILDS ONLY — never profile-armed (see
         * xenolith_guard::android_probes_for_profile). On this INIT_ARRAY
         * (dlopen) thread a successful TRACEME makes the parent — zygote on
         * real apps — the thread's tracer, and ptrace has no tracee-side
         * detach: the next signal delivered to this thread (ART suspension,
         * SIGQUIT, any directed signal, even SIG_IGN'd synchronous faults)
         * enters signal-delivery-stop and is never resumed. The app freezes
         * until SIGKILL (verified on Linux, independent review 2026-10-06).
         * Arming requires a parent that resumes tracee stops. */
        long rc = xl_sys3(XL_SYS_PTRACE, 0 /* PTRACE_TRACEME */, 0, 0);
        if (rc != 0) {
            /* TRACEME refused: either policy denied it (Yama/SELinux on
             * some contexts — TracerPid stays 0, NOT a hit) or someone
             * else already holds the tracer slot (TracerPid != 0 and !=
             * ppid → hit). classify() resolves the trichotomy. */
            if (!xl_read_status_tracer_pid(&tp)) return 0;
            if (xl_classify_tracerpid(tp, ppid) == XL_TRACER_HIT) return 0;
        }
        /* Success: the parent now occupies the tracer slot; later external
         * PTRACE_ATTACH is refused by the kernel. Residue on re-activation
         * is BenignSelf by construction (classify above). The freeze
         * exposure above is the price — hence not a default probe. */
    }
    if (probe_mask & XL_PROBE_BIT_MAPS) {
        if (xl_maps_contains_marker() != 0) return 0;
    }
    return 1;
}
#endif /* __aarch64__ */

#if defined(_MSC_VER)
#pragma optimize("", off)
#else
#pragma GCC push_options
#pragma GCC optimize("O0")
#endif

static int xl_build_region_table(XlHostCtx *ctx, XlRegionTable *rt) {
    const uint8_t *env = ctx->envelope;
    uint32_t env_len = ctx->envelope_len;
    uint32_t region_count, cur, i;
    const uint8_t *mba;
    if (env_len < 16 + 96 + 16 + 16 + 8 + 2) return 0;
    if (env[0] != 'X' || env[1] != 'L' || env[2] != 'V' || env[3] != '2') return 0;
    region_count = rd32(env + 12);
    if (region_count > 64) return 0;
    cur = 16;
    mba = env + cur;
    cur = xl_policy_off(env) + 4;
    for (i = 0; i < region_count; i++) {
        uint32_t index, rva, len, ct_len;
        if (cur + 4 + 4 + 4 + 12 + 4 > env_len) return 0;
        index = rd32(env + cur);
        rva = rd32(env + cur + 4);
        len = rd32(env + cur + 8);
        cur += 4 + 4 + 4 + 12;
        ct_len = rd32(env + cur); cur += 4;
        if (ct_len > XL_MAX_REGION || len > XL_MAX_REGION || cur + ct_len + 16 > env_len) return 0;
        rt->st[i].rva = rva;
        rt->st[i].len = len;
        rt->st[i].index = index;
        rt->st[i].rec_off = cur - (4 + 4 + 4 + 12 + 4);
        rt->st[i].state = XL_REGION_LIVE;
        rt->st[i].lazy = 0;
        rt->st[i].refcount = 0;
        cur += ct_len + 16;
    }
    /* skip imports */
    if (cur + 4 > env_len) return 0;
    {
        uint32_t n = rd32(env + cur); cur += 4;
        uint32_t imp_sealed = rd32(env + 8) & 0x2u;
        for (i = 0; i < n; i++) {
            uint32_t name_len, dll_len, payload;
            if (cur + 32 + 4 + 2 + 2 > env_len) return 0;
            cur += 32 + 4;
            name_len = rd16(env + cur); cur += 2;
            dll_len = rd16(env + cur); cur += 2;
            payload = name_len + dll_len;
            if (imp_sealed) payload += 12 + 16;
            if (cur + payload > env_len) return 0;
            cur += payload;
        }
    }
    /* skip keep list */
    if (cur + 4 > env_len) return 0;
    {
        uint32_t n = rd32(env + cur); cur += 4;
        if (cur + n * 4 > env_len) return 0;
        cur += n * 4;
    }
    /* skip reloc table */
    if (cur + 4 <= env_len) {
        uint32_t n = rd32(env + cur); cur += 4;
        if (cur + n * 8 > env_len) return 0;
        cur += n * 8;
        rt->reloc_bytes = n * 8u;
    } else {
        rt->reloc_bytes = 0;
    }
    /* lazy table */
    if (cur + 4 <= env_len) {
        uint32_t n = rd32(env + cur); cur += 4;
        for (i = 0; i < n; i++) {
            uint32_t idx;
            if (cur + 4 > env_len) return 0;
            idx = rd32(env + cur); cur += 4;
            if (idx < region_count) rt->st[idx].lazy = 1;
        }
    }
    if (!reconstruct_mba(mba, rt->secret)) return 0;
    mix_key(rt->secret, ctx->measurement, rt->runtime);
    rt->count = region_count;
    rt->ok = 1;
    return 1;
}

static int xl_region_open(XlHostCtx *ctx, XlRegionTable *rt, uint32_t i) {
    const uint8_t *env = ctx->envelope;
    uint32_t rec = rt->st[i].rec_off;
    uint32_t rva = rd32(env + rec + 4);
    uint32_t len = rd32(env + rec + 8);
    const uint8_t *nonce = env + rec + 12;
    uint32_t ct_len = rd32(env + rec + 24);
    const uint8_t *ct = env + rec + 28;
    const uint8_t *tag = ct + ct_len;
    uint8_t aad[32];
    uint8_t platform = env[6], profile = env[7];
    uint32_t flags = rd32(env + 8);
    uint32_t policy = rd32(env + xl_policy_off(env));
    uint32_t index = rd32(env + rec);
    uint8_t *dst = ctx->image_base + rva;
    uint32_t old = 0;
    region_aad(aad, platform, profile, flags, index, rva, len, policy, rt->reloc_bytes);
    if (!vp(ctx, dst, len, XL_PAGE_RW, &old)) return 0;
    if (!aead_open(rt->runtime, nonce, aad, 32, ct, ct_len, tag, dst)) return 0;
    if (!vp(ctx, dst, len, xl_final_protect(ctx, rva), &old)) return 0;
    rt->st[i].state = XL_REGION_LIVE;
    return 1;
}

static int xl_region_seal(XlHostCtx *ctx, XlRegionTable *rt, uint32_t i) {
    const uint8_t *env = ctx->envelope;
    uint32_t rec = rt->st[i].rec_off;
    uint32_t rva = rd32(env + rec + 4);
    uint32_t len = rd32(env + rec + 8);
    const uint8_t *nonce = env + rec + 12;
    uint32_t ct_len = rd32(env + rec + 24);
    const uint8_t *orig_ct = env + rec + 28;
    const uint8_t *orig_tag = orig_ct + ct_len;
    uint8_t aad[32];
    uint8_t platform = env[6], profile = env[7];
    uint32_t flags = rd32(env + 8);
    uint32_t policy = rd32(env + xl_policy_off(env));
    uint32_t index = rd32(env + rec);
    uint8_t *page = ctx->image_base + rva;
    uint8_t ct[XL_MAX_REGION];
    uint8_t tag[16];
    uint32_t old = 0, k;
    region_aad(aad, platform, profile, flags, index, rva, len, policy, rt->reloc_bytes);
    if (!vp(ctx, page, len, XL_PAGE_RW, &old)) return 0;
    aead_seal(rt->runtime, nonce, aad, 32, page, len, ct, tag);
    for (k = 0; k < len; k++) {
        if (ct[k] != orig_ct[k]) { vp(ctx, page, len, xl_final_protect(ctx, rva), &old); return 0; }
    }
    for (k = 0; k < 16; k++) {
        if (tag[k] != orig_tag[k]) { vp(ctx, page, len, xl_final_protect(ctx, rva), &old); return 0; }
    }
    for (k = 0; k < len; k++) page[k] = ct[k];
    if (!vp(ctx, page, len, 0x01u, &old)) return 0; /* PAGE_NOACCESS */
    rt->st[i].state = XL_REGION_SEALED;
    return 1;
}

/* Overlay the persisted seal state onto a freshly rebuilt table. Returns 0
 * if the persisted snapshot does not cover this envelope (state not yet
 * published or envelope shape changed). */
static int xl_state_overlay(XlGState *g, XlRegionTable *rt) {
    uint32_t i;
    if (g->rcount != rt->count) return 0;
    for (i = 0; i < rt->count; i++) rt->st[i].state = g->rstate[i];
    return 1;
}

int xl_core_fault(void *exc) {
    XlRegionTable rt;
    uint32_t code, i, nparams;
    const uint8_t *rec;
    uint64_t fault_addr, exec_addr, base;
    if (!g_xl.ok) return 0;
    rec = *(const uint8_t *const *)exc;
    code = rd32(rec);
    g_xl.dbg[0]++;
    g_xl.dbg[1] = code;
    g_xl.dbg[2] = 1;
    if (code != 0xC0000005u) return 0;
    /* Win64 EXCEPTION_RECORD: ExceptionAddress at +0x10, NumberParameters at
     * +0x18, ExceptionInformation[1] (data VA) at +0x28. Use the data VA
     * when present; fall back to ExceptionAddress for execute faults. */
    exec_addr = *(const uint64_t *)(rec + 0x10);
    nparams = rd32(rec + 0x18);
    fault_addr = (nparams >= 2) ? *(const uint64_t *)(rec + 0x28) : exec_addr;
    if (!xl_build_region_table(&g_xl.ctx, &rt)) { g_xl.dbg[2] = 3; return 0; }
    if (!xl_state_overlay(&g_xl, &rt)) { g_xl.dbg[2] = 4; return 0; }
    (void)0;
    base = (uint64_t)(uintptr_t)g_xl.ctx.image_base;
    g_xl.dbg[3] = (uint32_t)(fault_addr - base);
    for (i = 0; i < rt.count; i++) {
        uint64_t lo, hi;
        if (rt.st[i].state != XL_REGION_SEALED || !rt.st[i].lazy) continue;
        lo = base + rt.st[i].rva;
        hi = lo + rt.st[i].len;
        if ((fault_addr >= lo && fault_addr < hi) || (exec_addr >= lo && exec_addr < hi)) {
            if (xl_region_open(&g_xl.ctx, &rt, i)) {
                g_xl.rstate[i] = XL_REGION_LIVE;
                g_xl.dbg[2] = 2;
                return -1; /* CONTINUE_EXECUTION */
            }
            g_xl.dbg[2] = 5;
            return 0;
        }
    }
    return 0; /* CONTINUE_SEARCH */
}

/* Re-seal pass. Caller holds g_xl.quiescing. Returns 0 on success or the
 * 1-based region index whose provable re-seal failed. */
static int xl_quiesce_locked(uint32_t zero_keys) {
    XlRegionTable rt;
    uint32_t i, k;
    uint64_t rsp = (uint64_t)(uintptr_t)&rt;
    if (!xl_build_region_table(&g_xl.ctx, &rt)) return -1;
    if (!xl_state_overlay(&g_xl, &rt)) return -1;
    for (i = 0; i < rt.count; i++) {
        int in_use = 0;
        uint64_t lo, hi;
        if (!rt.st[i].lazy || rt.st[i].state != XL_REGION_LIVE) continue;
        if (rt.st[i].refcount != 0) continue;
        lo = (uint64_t)(uintptr_t)g_xl.ctx.image_base + rt.st[i].rva;
        hi = lo + rt.st[i].len;
        /* Only the CURRENT thread's stack is provably dead: a region still
         * referenced by it stays live. Regions executed only by OTHER
         * threads may be re-sealed here; their next fault wakes them. */
        for (k = 0; k < 0x800 && !in_use; k++) {
            uint64_t v = *(const uint64_t *)(const void *)(uintptr_t)(rsp + k * 8);
            if (v >= lo && v < hi) in_use = 1;
        }
        if (in_use) continue;
        if (!xl_region_seal(&g_xl.ctx, &rt, i)) return (int)(i + 1);
        g_xl.rstate[i] = XL_REGION_SEALED;
    }
    if (zero_keys) {
        /* Deregister the VEH BEFORE the keys die: after the module unmaps,
         * the handler pointer would dangle and any later exception in the
         * process would dispatch into unmapped memory. */
        if (g_xl.ctx.veh_remove && g_xl.ctx.veh_handle) {
            g_xl.ctx.veh_remove(g_xl.ctx.veh_handle);
            g_xl.ctx.veh_handle = 0;
        }
        xl_zero(rt.secret, 32);
        xl_zero(rt.runtime, 32);
        g_xl.ok = 0;
    }
    return 0;
}

#if defined(_MSC_VER)
#define XL_CAS_QUIESCING() \
    _InterlockedCompareExchange((volatile long *)&g_xl.quiescing, 1, 0)
#define XL_STORE_QUIESCING() \
    _InterlockedExchange((volatile long *)&g_xl.quiescing, 0)
#else
/* GCC/clang: same acquire-CAS / release-store contract without MSVC-only
 * Interlocked intrinsics (they would be undefined externals in the ELF
 * object runtime_image rejects). */
#define XL_CAS_QUIESCING() \
    __atomic_compare_exchange_n((volatile int *)&g_xl.quiescing, \
                                &(int){0}, 1, 0, \
                                __ATOMIC_ACQUIRE, __ATOMIC_ACQUIRE)
#define XL_STORE_QUIESCING() \
    __atomic_store_n((volatile int *)&g_xl.quiescing, 0, __ATOMIC_RELEASE)
#endif

int xl_core_quiesce(uint32_t zero_keys) {
    int ret;
    uint32_t spin = 0;
    if (!g_xl.ok) return -1;
    while (!XL_CAS_QUIESCING()) {
        /* Bounded spin, then proceed anyway: over-eager concurrent seals
         * write identical bytes and any premature seal is recovered by
         * wake-on-fault, so livelock is worse than a benign race. */
        if (++spin > 0x400000u) break;
    }
    ret = xl_quiesce_locked(zero_keys);
    XL_STORE_QUIESCING();
    return ret;
}

int xl_core_activate(XlHostCtx *ctx) {
    const uint8_t *env;
    uint32_t env_len;
    uint8_t platform, profile, gate;
    uint32_t flags, region_count, policy;
    const uint8_t *mba;
    uint32_t cur;
    uint32_t stolen_len, prog_len;
    uint32_t reloc_bytes;
    uint64_t delta;
    const uint8_t *stolen;
    uint8_t secret[32], runtime[32];
    uint32_t i;

    if (!ctx || !ctx->image_base || !ctx->envelope) return 0;
    env = ctx->envelope;
    env_len = ctx->envelope_len;
    gate = ctx->debug_gate;
    if (env_len < 16 + 96 + 16 + 16 + 8 + 2) return 0;
    if (env[0] != 'X' || env[1] != 'L' || env[2] != 'V' || env[3] != '2') return 0;
    if (rd16(env + 4) != 2) return 0;
    if (gate == 0) return 1;

    platform = env[6];
    if (platform != XL_PLATFORM_PE64 && platform != XL_PLATFORM_ELF64 &&
        platform != XL_PLATFORM_ELF64_AARCH64) return 0; /* unknown platform: fail closed */
#if defined(__aarch64__)
    /* Android guard: probes run after the platform gate and BEFORE any
     * AEAD open (plan WS-A §2.2.2) — mirroring the Windows stub, which
     * runs its debugger checks before xl_core_activate is ever reached.
     * A fired probe (or an unreadable /proc) fails the whole activation;
     * there is no logging channel and no partial-unpack fallback. */
    if (platform == XL_PLATFORM_ELF64_AARCH64) {
        if (!xl_android_guard(ctx->probe_mask)) return 0;
    }
#endif
    profile = env[7];
    flags = rd32(env + 8);
    region_count = rd32(env + 12);
    cur = 16;
    if (cur + 96 + 16 + 16 + 8 + 2 > env_len) return 0;
    mba = env + cur; cur += 96;
    cur += 16; /* seed */
    cur += 16; /* salt */
    cur += 8;  /* opcode map */
    stolen_len = rd16(env + cur); cur += 2;
    if (cur + stolen_len + 4 > env_len) return 0;
    stolen = env + cur; cur += stolen_len;
    prog_len = rd32(env + cur); cur += 4;
    if (cur + prog_len + 4 > env_len) return 0;
    cur += prog_len;
    policy = rd32(env + cur); cur += 4;
    (void)platform;
    (void)flags;
    if (!reconstruct_mba(mba, secret)) { return 0; }
    mix_key(secret, ctx->measurement, runtime);

    /* The region AAD must carry the reloc-table byte length exactly like the
     * packer's seal (record count * 8 in the tail dword) — without it every
     * open fails for envelopes that carry at least one reloc record. The
     * same bounded pre-scan also recovers the ASLR delta from the loader's
     * fixups over the 0xCC page filler, and it MUST run before the decrypt
     * loop below overwrites those slots with their unrelocated plaintext. */
    /* PE (platform 0) only: the 0xCC filler + DIR64 delta recovery. Both
     * ELF platforms (1 = AMD64, 2 = AArch64/Android) leave ld.so's own
     * relocations untouched — no delta to recover. */
    if (!xl_reloc_scan(env, env_len, ctx->image_base, platform == XL_PLATFORM_PE64,
                       &reloc_bytes, &delta)) {
        return 0;
    }

    if (gate >= 2) {
        for (i = 0; i < region_count; i++) {
            uint32_t index, rva, len, ct_len;
            const uint8_t *nonce;
            const uint8_t *ct;
            const uint8_t *tag;
            uint8_t aad[32];
            if (cur + 4 + 4 + 4 + 12 + 4 > env_len) return 0;
            index = rd32(env + cur); cur += 4;
            rva = rd32(env + cur); cur += 4;
            len = rd32(env + cur); cur += 4;
            nonce = env + cur; cur += 12;
            ct_len = rd32(env + cur); cur += 4;
            if (ct_len > XL_MAX_REGION || len > XL_MAX_REGION || cur + ct_len + 16 > env_len) return 0;
            ct = env + cur; cur += ct_len;
            tag = env + cur; cur += 16;
            region_aad(aad, platform, profile, flags, index, rva, len, policy, reloc_bytes);
            if (len > ct_len) return 0;
            {
                uint8_t *dst = ctx->image_base + rva;
                uint32_t old = 0;
                if (!vp(ctx, dst, len, XL_PAGE_RW, &old)) { return 0; }
                if (!aead_open(runtime, nonce, aad, 32, ct, ct_len, tag, dst)) { return 0; }
                /* xl_final_protect: restore what the region's own section/
                 * segment declares (RX normally; RWX sections stay writable),
                 * never the vp-reported `old` (sealed NOACCESS on wake, or the
                 * echoed request constant on the ELF mprotect shim). */
                if (!vp(ctx, dst, len, xl_final_protect(ctx, rva), &old)) { return 0; }
            }
        }
    } else {
        /* Skip region records so imports/stolen still parse for gate 1. */
        for (i = 0; i < region_count; i++) {
            uint32_t ct_len;
            if (cur + 4 + 4 + 4 + 12 + 4 > env_len) return 0;
            cur += 4 + 4 + 4 + 12;
            ct_len = rd32(env + cur); cur += 4;
            if (cur + ct_len + 16 > env_len) return 0;
            cur += ct_len + 16;
        }
    }

    if (gate < 3) {
        uint32_t import_count;
        uint32_t imp_sealed = flags & 0x2u;
        if (cur + 4 > env_len) return 0;
        import_count = rd32(env + cur); cur += 4;
        for (i = 0; i < import_count; i++) {
            uint16_t name_len, dll_len;
            uint32_t payload;
            if (cur + 32 + 4 + 2 + 2 > env_len) return 0;
            cur += 32 + 4;
            name_len = rd16(env + cur); cur += 2;
            dll_len = rd16(env + cur); cur += 2;
            payload = (uint32_t)name_len + dll_len;
            if (imp_sealed) payload += 12 + 16;
            if (cur + payload > env_len) return 0;
            cur += payload;
        }
    } else {
        uint32_t import_count;
        uint32_t imp_sealed = flags & 0x2u;
        if (cur + 4 > env_len) return 0;
        import_count = rd32(env + cur); cur += 4;
        for (i = 0; i < import_count; i++) {
            uint32_t iat_rva;
            uint16_t name_len, dll_len;
            /* Import names ride the envelope as raw u16-length bytes; real
             * C++ mangled names run well past 255 (libclang-cpp ships 526-
             * byte symbols). The old 256-byte buffers made activate fail
             * closed on every such import (DllMain-false -> loader exit
             * ERROR_DLL_INIT_FAILED) although the original DLL loaded fine.
             * 2 KB covers the mangled-name ceiling on all toolchains; the
             * length check below now derives from the buffer, not a magic
             * constant, so overlong records still fail closed - just at the
             * true buffer limit instead of 255. */
            char name[2048];
            char dll[2048];
            void *mod;
            void *fn;
            uint32_t old = 0;
            uint8_t *slot;
            if (cur + 32 + 4 + 2 + 2 > env_len) return 0;
            cur += 32;
            iat_rva = rd32(env + cur); cur += 4;
            name_len = rd16(env + cur); cur += 2;
            dll_len = rd16(env + cur); cur += 2;
            if ((uint32_t)name_len >= sizeof(name) || (uint32_t)dll_len >= sizeof(dll)) return 0;
            if (imp_sealed) {
                /* TASK-024: sealed name||dll. Fail closed on any tamper. */
                const uint8_t *nonce = env + cur;
                const uint8_t *tag = nonce + 12;
                const uint8_t *ct = tag + 16;
                uint8_t aad[32];
                uint8_t pt[2048 + 2048];  /* name||dll sealed payload cap */
                if (cur + 12 + 16 + (uint32_t)name_len + dll_len > env_len) return 0;
                import_aad(aad, platform, flags, iat_rva, name_len, dll_len, i);
                if (!aead_open(runtime, nonce, aad, 32, ct,
                               (uint32_t)name_len + dll_len, tag, pt)) return 0;
                xl_zero((uint8_t *)name, sizeof(name));
                xl_zero((uint8_t *)dll, sizeof(dll));
                xl_copy((uint8_t *)name, pt, name_len);
                xl_copy((uint8_t *)dll, pt + name_len, dll_len);
                cur += 12 + 16 + (uint32_t)name_len + dll_len;
            } else {
                if (cur + (uint32_t)name_len + dll_len > env_len) return 0;
                xl_zero((uint8_t *)name, sizeof(name));
                xl_zero((uint8_t *)dll, sizeof(dll));
                xl_copy((uint8_t *)name, env + cur, name_len); cur += name_len;
                xl_copy((uint8_t *)dll, env + cur, dll_len); cur += dll_len;
            }
            if (!ctx->load_library || !ctx->get_proc) {
                continue;
            }
            if (flags & 0x4u) {
                /* FLAG_LOADER_RESOLVED_IAT: the on-disk import directory is
                 * retained, so the OS loader has already filled the IAT
                 * before this stub ran. Re-binding through our own search
                 * order only risks failure (the host EXE's directory is
                 * searched first, not this module's), so skip binding and
                 * just walk the records to reach the keep-list/relocs. */
                continue;
            }
            /* Loader-faithful binding order. The OS loader resolves a
             * module's dependencies through the STANDARD search order
             * (host exe dir, system dirs, ..., CWD); the dependent-DLL
             * search does NOT put this module's own directory ahead of
             * system32. Two failure modes shaped this code:
             *  - preferring the module directory first picked up shipping
             *    apps' stale LOCAL copies of system DLLs (an old
             *    msvcrt.dll shipped next to dbgeng.dll) whose load
             *    poisons later system-module loads (ADVAPI32 then fails
             *    with ERROR_PROC_NOT_FOUND);
             *  - a bare name alone loses sibling DLLs when the host CWD
             *    is not the module directory.
             * Bind by plain name first (exactly what the loader does),
             * and only when that fails fall back to "<module dir>\<dep>"
             * via LoadLibraryExA. API-set names (api-ms-*, ext-ms-*) are
             * virtual: the loader never touches disk for them and apps
             * ship real stub FILES with those names, so they never take
             * the path fallback. */
            mod = ctx->load_library(dll);
            if (!mod && ctx->load_library_ex && dll_len < 256
                && !(dll_len >= 7
                     && (dll[0] == 'a' || dll[0] == 'e')
                     && dll[1] == 'p' && dll[2] == 'i' && dll[3] == '-'
                     && dll[4] == 'm' && dll[5] == 's' && dll[6] == '-')) {
                char dir[264];
                char dep[536];
                uint32_t dl = xl_module_dir(ctx, dir, (uint32_t)sizeof(dir));
                if (dl != 0 && dl + dll_len + 1 <= (uint32_t)sizeof(dep)) {
                    uint32_t k;
                    for (k = 0; k < dl; k++) dep[k] = dir[k];
                    for (k = 0; k < dll_len; k++) dep[dl + k] = dll[k];
                    dep[dl + dll_len] = 0;
                    mod = ctx->load_library_ex(dep, (void *)0, 0x8u);
                }
            }
            if (!mod) return 0;
            /* Ordinal imports arrive under the reserved display name
             * "#<decimal ordinal>" (packer convention; see docs/SUPPORT.md).
             * GetProcAddress reads a name pointer below 0x10000 as an
             * ordinal — the MAKEINTRESOURCE channel — so "#42" binds
             * GetProcAddress(mod, (LPCSTR)42). A name that merely starts
             * with '#' but is not fully numeric binds by name and fails
             * closed below like any other unresolved import. */
            {
                int is_ordinal = 0;
                uint32_t ord = 0;
                if (name[0] == '#') {
                    const char *p = name + 1;
                    uint32_t digits = 0;
                    while (*p >= '0' && *p <= '9') {
                        ord = ord * 10u + (uint32_t)(*p - '0');
                        digits++;
                        p++;
                    }
                    if (digits > 0 && *p == '\0') is_ordinal = 1;
                }
                fn = is_ordinal
                    ? ctx->get_proc(mod, (const char *)(uintptr_t)ord)
                    : ctx->get_proc(mod, name);
            }
            if (!fn) { return 0; }
            slot = ctx->image_base + iat_rva;
            if (!vp(ctx, slot, 8, XL_PAGE_RW, &old)) { return 0; }
            *(void **)slot = fn;
            if (!vp(ctx, slot, 8, old, &old)) { return 0; }
        }
    }

    /* skip keep-list */
    if (cur + 4 > env_len) return 0;
    {
        uint32_t kc = rd32(env + cur);
        cur += 4;
        if (cur + kc * 4 > env_len) return 0;
        cur += kc * 4;
    }
    if (gate >= 2) {
        /* ELF (1 = AMD64, 2 = AArch64): ld.so already applied RELATIVE.
         * PE ImageBase parse is wrong here. */
        if (platform == XL_PLATFORM_ELF64 || platform == XL_PLATFORM_ELF64_AARCH64) {
            uint32_t n;
            if (cur + 4 > env_len) return 0;
            n = rd32(env + cur);
            cur += 4;
            if (cur + n * 8 > env_len) return 0;
            cur += n * 8;
        } else if (!apply_dir64(ctx, env, env_len, &cur, delta)) {
            return 0;
        }
    }

    if (gate >= 1) {
        if (!copy_rx(ctx, ctx->image_base + ctx->original_entry_rva, stolen, (uint32_t)stolen_len, XL_PAGE_RX))
            return 0;
    }

    (void)policy;
    /* G5: publish the context for the fault/quiesce entry points, then put
     * every lazy region to sleep: re-seal (deterministic replay, verified
     * against the on-disk record) and drop all access. Keep-set regions
     * (entry page, exports, resolver pages) stay live for the loader path. */
    if (gate >= 3 && ctx->image_base && ctx->envelope) {
        XlRegionTable rt;
        uint32_t i;
        uint32_t old_prot = 0;
        /* Skip the whole G5 publish when no lazy regions exist: the state
         * block is not embedded in that build, and touching it would flip
         * an unrelated stub page RW (stripping X). */
        uint32_t has_lazy = 0;
        {
            uint32_t cur2 = 16 + 96 + 16 + 16 + 8;
            uint32_t n = rd32(ctx->envelope + 12);
            uint32_t i2;
            cur2 += 2 + rd16(ctx->envelope + cur2);
            cur2 += 4 + rd32(ctx->envelope + cur2);
            cur2 += 4; /* policy */
            for (i2 = 0; i2 < n; i2++) {
                uint32_t ct_len2;
                cur2 += 4 + 4 + 4 + 12;
                ct_len2 = rd32(ctx->envelope + cur2); cur2 += 4 + ct_len2 + 16;
            }
            /* imports */
            n = rd32(ctx->envelope + cur2); cur2 += 4;
            {
                uint32_t imp_sealed = rd32(ctx->envelope + 8) & 0x2u;
                for (i2 = 0; i2 < n; i2++) {
                    uint32_t nl, dl, payload;
                    cur2 += 32 + 4;
                    nl = rd16(ctx->envelope + cur2); cur2 += 2;
                    dl = rd16(ctx->envelope + cur2); cur2 += 2;
                    payload = nl + dl;
                    if (imp_sealed) payload += 12 + 16;
                    cur2 += payload;
                }
            }
            /* keep */
            n = rd32(ctx->envelope + cur2); cur2 += 4 + n * 4;
            /* relocs */
            if (cur2 + 4 <= ctx->envelope_len) {
                n = rd32(ctx->envelope + cur2); cur2 += 4 + n * 8;
            }
            /* lazy table */
            if (cur2 + 4 <= ctx->envelope_len) {
                has_lazy = rd32(ctx->envelope + cur2);
            }
        }
        if (has_lazy == 0) {
            return 1;
        }
        /* g_xl rides inside the RX stub section; make just its range
         * writable for the lifetime (state + key zeroize on quiesce). */
        vp(ctx, (void *)&g_xl, sizeof(g_xl), XL_PAGE_RW, &old_prot);
        g_xl.ctx = *ctx;
        g_xl.ok = 1;
        /* Fail closed: with lazy regions pending, a table we cannot rebuild
         * means they would never wake from a seal. */
        if (!xl_build_region_table(&g_xl.ctx, &rt)) return 0;
        for (i = 0; i < rt.count; i++) {
            if (rt.st[i].lazy && !xl_region_seal(&g_xl.ctx, &rt, i)) {
                /* A lazy page that cannot be provably re-sealed fails
                 * closed: the image must not run with dormant plaintext. */
                return 0;
            }
            g_xl.rstate[i] = rt.st[i].lazy ? XL_REGION_SEALED : XL_REGION_LIVE;
        }
        g_xl.rcount = rt.count;
    }
    return 1;
}

#if defined(_MSC_VER)
#pragma optimize("", on)
#else
#pragma GCC pop_options
#endif
