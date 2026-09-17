/* TASK-022 driver: pack the feature .so and exercise IFUNC, versioned
 * symbols (dlvsym), and both TLS models through dlopen. */
#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>
#include <stdint.h>

int main(int argc, char **argv) {
    (void)argc;
    void *h = dlopen(argv[1], RTLD_NOW);
    if (!h) { printf("DLOPEN FAIL %s\n", dlerror()); return 1; }

    uint64_t (*ia)(uint64_t, uint64_t) = (uint64_t (*)(uint64_t, uint64_t))dlsym(h, "ifunc_add");
    if (!ia) { printf("DLSYM ifunc_add FAIL\n"); return 2; }
    uint64_t r = ia(10, 5);
    if (r != 15) { printf("IFUNC %llu\n", (unsigned long long)r); return 3; }

    uint32_t (*v1)(uint32_t) = (uint32_t (*)(uint32_t))dlvsym(h, "feat_ver", "XLFEAT_1.0");
    uint32_t (*p2)(uint32_t) = (uint32_t (*)(uint32_t))dlvsym(h, "feat_ver", "XLFEAT_2.0");
    if (!v1 || !p2) { printf("DLVSYM FAIL v1=%p v2=%p\n", (void *)v1, (void *)p2); return 4; }
    if (v1(2) != 107) { printf("VER1 %u\n", v1(2)); return 5; }
    if (p2(2) != 207) { printf("VER2 %u\n", p2(2)); return 6; }
    if ((void *)v1 == (void *)p2) { printf("VERSIONS ALIAS\n"); return 7; }

    uint64_t (*tb)(uint64_t) = (uint64_t (*)(uint64_t))dlsym(h, "tls_bump");
    uint64_t (*tg)(void) = (uint64_t (*)(void))dlsym(h, "tls_get");
    uint64_t (*fa)(uint64_t) = (uint64_t (*)(uint64_t))dlsym(h, "feat_all");
    if (!tb || !tg || !fa) { printf("DLSYM TLS FAIL\n"); return 8; }
    tb(3);
    uint64_t t = tg();
    if (t != 3 + 6 + 9) { printf("TLS %llu\n", (unsigned long long)t); return 9; }
    uint64_t all = fa(7);
    if (all == 0) { printf("FEAT_ALL ZERO\n"); return 10; }

    printf("FEAT MATRIX OK (ifunc=%llu ver1=%u ver2=%u tls=%llu all=%llu)\n",
           (unsigned long long)r, v1(2), p2(2), (unsigned long long)t,
           (unsigned long long)all);
    return 0;
}
