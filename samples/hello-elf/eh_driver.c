#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>
#include <stdint.h>
#include <string.h>
#include <unwind.h>

static int frames;

static _Unwind_Reason_Code bt(struct _Unwind_Context *ctx, void *d) {
    (void)ctx;
    (void)d;
    frames++;
    return _URC_NO_REASON;
}

static int cb(void *user, int x) {
    (void)user;
    _Unwind_Backtrace(bt, 0);
    return x * 2;
}

int main(int argc, char **argv) {
    (void)argc;
    void *h = dlopen(argv[1], RTLD_NOW);
    if (!h) { printf("DLOPEN FAIL %s\n", dlerror()); return 1; }
    int (*tc)(int) = (int (*)(int))dlsym(h, "eh_throw_catch");
    int (*ua)(int) = (int (*)(int))dlsym(h, "eh_unwind_across");
    int (*sj)(int) = (int (*)(int))dlsym(h, "sj_probe");
    int (*vs)(int, ...) = (int (*)(int, ...))dlsym(h, "vararg_sum");
    long long (*sr)(int) = (long long (*)(int))dlsym(h, "struct_ret");
    int (*tl)(int) = (int (*)(int))dlsym(h, "tail_call");
    int (*wc)(int (*)(void *, int), void *, int) =
        (int (*)(int (*)(void *, int), void *, int))dlsym(h, "with_callback");
    if (!tc || !ua || !sj || !vs || !sr || !tl || !wc) {
        printf("DLSYM FAIL\n");
        return 2;
    }
    if (tc(5) != 47) { printf("THROW %d\n", tc(5)); return 3; }
    if (ua(3) != 103) { printf("UNWIND %d\n", ua(3)); return 4; }
    if (sj(4) != 1004) { printf("SJ\n"); return 5; }
    if (vs(3, 10, 20, 30) != 60) { printf("VARARG\n"); return 6; }
    /* 8-byte struct returned in RAX on SysV: {a=x+1, b=x*2} = a | b<<32 */
    long long p = sr(7);
    if ((int)(p & 0xffffffff) != 8 || (int)(p >> 32) != 14) { printf("STRUCT %llx\n", p); return 7; }
    if (tl(9) != 10) { printf("TAIL\n"); return 8; }
    frames = 0;
    int r = wc(cb, 0, 21);
    if (r != 43) { printf("CB %d\n", r); return 9; }
    if (frames < 3) { printf("BT FRAMES %d\n", frames); return 10; }
    printf("ELF EH MATRIX OK (backtrace frames=%d)\n", frames);
    return 0;
}
