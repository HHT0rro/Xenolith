/* TASK-022 driver: pack the feature .so and exercise IFUNC, versioned
 * symbols (dlvsym), and both TLS models through dlopen. */
#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>
#include <stdint.h>

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <shared-library>\n", argv[0]);
        return 2;
    }
    void *h = dlopen(argv[1], RTLD_NOW);
    if (!h) { printf("DLOPEN FAIL %s\n", dlerror()); return 1; }

    uint64_t (*ia)(uint64_t, uint64_t) = (uint64_t (*)(uint64_t, uint64_t))dlsym(h, "ifunc_add");
    if (!ia) { printf("DLSYM ifunc_add FAIL\n"); return 2; }
    uint64_t r = ia(10, 5);
    if (r != 15) { printf("IFUNC %llu\n", (unsigned long long)r); return 3; }

    uint32_t (*v1)(uint32_t) = (uint32_t (*)(uint32_t))dlvsym(h, "feat_ver", "XLFEAT_1.0");
    uint32_t (*p2)(uint32_t) = (uint32_t (*)(uint32_t))dlvsym(h, "feat_ver", "XLFEAT_2.0");
    if (!v1 || !p2) { printf("DLVSYM FAIL v1=%p v2=%p\n", (void *)v1, (void *)p2); return 4; }
    uint32_t ver1 = v1(2);
    uint32_t ver2 = p2(2);
    if (ver1 != 107) { printf("VER1 %u\n", ver1); return 5; }
    if (ver2 != 207) { printf("VER2 %u\n", ver2); return 6; }
    if ((void *)v1 == (void *)p2) { printf("VERSIONS ALIAS\n"); return 7; }
    uint32_t (*current)(uint32_t) = (uint32_t (*)(uint32_t))dlsym(h, "feat_ver");
    if (current != p2) { printf("DEFAULT VERSION FAIL\n"); return 11; }

    uint64_t (*tb)(uint64_t) = (uint64_t (*)(uint64_t))dlsym(h, "tls_bump");
    uint64_t (*tg)(void) = (uint64_t (*)(void))dlsym(h, "tls_get");
    uint64_t (*fa)(uint64_t) = (uint64_t (*)(uint64_t))dlsym(h, "feat_all");
    if (!tb || !tg || !fa) { printf("DLSYM TLS FAIL\n"); return 8; }
    if (tg() != 0) { printf("TLS INITIAL VALUE\n"); return 12; }
    uint64_t bumped = tb(3);
    if (bumped != 6010) { printf("TLS BUMP %llu\n", (unsigned long long)bumped); return 13; }
    uint64_t t = tg();
    if (t != 3 + 6 + 9) { printf("TLS %llu\n", (unsigned long long)t); return 9; }
    uint64_t all = fa(7);
    if (all != 244) { printf("FEAT_ALL %llu\n", (unsigned long long)all); return 10; }
    if (tg() != 30) { printf("TLS AFTER FEAT_ALL\n"); return 14; }
    if (dlclose(h) != 0) { printf("DLCLOSE FAIL %s\n", dlerror()); return 15; }

    printf("FEAT MATRIX OK (ifunc=%llu ver1=%u ver2=%u tls=%llu all=%llu)\n",
           (unsigned long long)r, ver1, ver2, (unsigned long long)t,
           (unsigned long long)all);
    return 0;
}
