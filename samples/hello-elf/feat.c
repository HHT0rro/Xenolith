/* TASK-022 frozen matrix (Linux): IFUNC selection, symbol versions,
 * and the common TLS models (initial-exec + local-dynamic). Packed and
 * exercised through dlopen in WSL. */
#include <stdint.h>
#include <string.h>

#if defined(_WIN32)
#define XL_EXPORT __declspec(dllexport)
#else
#define XL_EXPORT __attribute__((visibility("default")))
#endif

/* ---------------- IFUNC ---------------- */
static uint64_t add_scalar(uint64_t x, uint64_t n) {
    uint64_t r = x;
    for (uint64_t i = 0; i < n; i++) r = r + 1;
    return r;
}

static uint64_t add_unrolled(uint64_t x, uint64_t n) {
    uint64_t r = x;
    uint64_t q = n / 4, rem = n % 4;
    for (uint64_t i = 0; i < q; i++) {
        r = r + 1;
        r = r + 1;
        r = r + 1;
        r = r + 1;
    }
    for (uint64_t i = 0; i < rem; i++) r = r + 1;
    return r;
}

/* Resolver: forces an R_X86_64_IRELATIVE into .rela.dyn (executed by ld.so
 * BEFORE the packed init runs). */
static uint64_t (*resolve_add(void))(uint64_t, uint64_t) {
    /* sizeof-based selector keeps it a real (non-constant) resolver */
    return (sizeof(uintptr_t) == 8 && ((uintptr_t)&add_unrolled & 1) == 0)
               ? add_unrolled
               : add_scalar;
}

XL_EXPORT uint64_t ifunc_add(uint64_t x, uint64_t n) __attribute__((ifunc("resolve_add")));

/* ---------------- symbol versions ---------------- */
__asm__(".symver feat_ver_v1, feat_ver@XLFEAT_1.0");
__asm__(".symver feat_ver_v2, feat_ver@@XLFEAT_2.0");

uint32_t feat_ver_impl(uint32_t x) { return x * 3 + 1; }
XL_EXPORT uint32_t feat_ver_v1(uint32_t x) { return feat_ver_impl(x) + 100; }
XL_EXPORT uint32_t feat_ver_v2(uint32_t x) { return feat_ver_impl(x) + 200; }

/* ---------------- TLS: initial-exec + local-dynamic ---------------- */
static __thread uint64_t ie_counter __attribute__((tls_model("initial-exec")));
static __thread uint64_t ld_a __attribute__((tls_model("local-dynamic")));
static __thread uint64_t ld_b __attribute__((tls_model("local-dynamic")));

XL_EXPORT uint64_t tls_bump(uint64_t n) {
    for (uint64_t i = 0; i < n; i++) {
        ie_counter += 1;
        ld_a += 2;
        ld_b += 3;
    }
    return ie_counter ^ (ld_a * 1000) + ld_b;
}

XL_EXPORT uint64_t tls_get(void) {
    return ie_counter + ld_a + ld_b;
}

/* ---------------- cross-feature smoke ---------------- */
XL_EXPORT uint64_t feat_all(uint64_t x) {
    tls_bump(2);
    return ifunc_add(x, 3) + feat_ver_v2(1) + tls_get();
}
