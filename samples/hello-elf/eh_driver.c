#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>
#include <stdint.h>
#include <string.h>
#include <unwind.h>

struct Pair { int a; int b; };

static int frames;
static int library_frames;
static void *library_base;

static _Unwind_Reason_Code bt(struct _Unwind_Context *ctx, void *d) {
    (void)d;
    frames++;
    uintptr_t pc = (uintptr_t)_Unwind_GetIP(ctx);
    Dl_info info;
    if (pc && dladdr((void *)(pc - 1), &info) && info.dli_fbase == library_base) {
        library_frames++;
    }
    return _URC_NO_REASON;
}

static int cb(void *user, int x) {
    (void)user;
    _Unwind_Backtrace(bt, 0);
    return x * 2;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <shared-library>\n", argv[0]);
        return 2;
    }
    void *h = dlopen(argv[1], RTLD_NOW);
    if (!h) { printf("DLOPEN FAIL %s\n", dlerror()); return 1; }
    int (*tc)(int) = (int (*)(int))dlsym(h, "eh_throw_catch");
    int (*ua)(int) = (int (*)(int))dlsym(h, "eh_unwind_across");
    int (*sj)(int) = (int (*)(int))dlsym(h, "sj_probe");
    int (*vs)(int, ...) = (int (*)(int, ...))dlsym(h, "vararg_sum");
    struct Pair (*sr)(int) = (struct Pair (*)(int))dlsym(h, "struct_ret");
    int (*tl)(int) = (int (*)(int))dlsym(h, "tail_call");
    int (*wc)(int (*)(void *, int), void *, int) =
        (int (*)(int (*)(void *, int), void *, int))dlsym(h, "with_callback");
    if (!tc || !ua || !sj || !vs || !sr || !tl || !wc) {
        printf("DLSYM FAIL\n");
        return 2;
    }
    int thrown = tc(5);
    if (thrown != 47) { printf("THROW %d\n", thrown); return 3; }
    int unwound = ua(3);
    if (unwound != 103) { printf("UNWIND %d\n", unwound); return 4; }
    if (sj(4) != 1004) { printf("SJ\n"); return 5; }
    if (vs(3, 10, 20, 30) != 60) { printf("VARARG\n"); return 6; }
    struct Pair p = sr(7);
    if (p.a != 8 || p.b != 14) { printf("STRUCT %d %d\n", p.a, p.b); return 7; }
    if (tl(9) != 10) { printf("TAIL\n"); return 8; }
    frames = 0;
    library_frames = 0;
    Dl_info info;
    if (!dladdr((void *)wc, &info)) { printf("CALLBACK DLADDR FAIL\n"); return 11; }
    library_base = info.dli_fbase;
    int r = wc(cb, 0, 21);
    if (r != 43) { printf("CB %d\n", r); return 9; }
    if (frames < 3) { printf("BT FRAMES %d\n", frames); return 10; }
    if (library_frames == 0) { printf("BT MISSED LIBRARY\n"); return 12; }
    if (dlclose(h) != 0) { printf("DLCLOSE FAIL %s\n", dlerror()); return 13; }
    printf("ELF EH MATRIX OK (backtrace frames=%d)\n", frames);
    return 0;
}
