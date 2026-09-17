// TASK-021 frozen matrix (Linux): C++ exceptions, setjmp/longjmp, varargs,
// struct return, tail calls, and an unwinder callback — packed and
// exercised through dlopen in WSL.
#include <csetjmp>
#include <cstdarg>
#include <stdexcept>

#if defined(_WIN32)
#define XL_EXPORT extern "C" __declspec(dllexport)
#else
#define XL_EXPORT extern "C" __attribute__((visibility("default")))
#endif

static int throws_int(int) { throw std::runtime_error("boom"); }

XL_EXPORT int eh_throw_catch(int x) {
    try { throws_int(x); return -1; } catch (const std::exception &) { return 42 + x; }
}

XL_EXPORT int eh_unwind_across(int depth) {
    try {
        if (depth > 0) return eh_unwind_across(depth - 1) + 1;
        throws_int(0);
    } catch (const std::runtime_error &) { return 100 + depth; }
    return -2;
}

static jmp_buf g_jb;
XL_EXPORT int sj_probe(int x) {
    if (setjmp(g_jb) == 0) longjmp(g_jb, 7 + x);
    return 1000 + x;
}

XL_EXPORT int vararg_sum(int n, ...) {
    va_list ap;
    va_start(ap, n);
    int total = 0;
    for (int i = 0; i < n; i++) total += va_arg(ap, int);
    va_end(ap);
    return total;
}

struct Pair { int a; int b; };
XL_EXPORT struct Pair struct_ret(int x) {
    Pair p; p.a = x + 1; p.b = x * 2; return p;
}

static int inner(int x) { return x + 1; }
XL_EXPORT int tail_call(int x) { return inner(x); }

// Invokes cb while this (packed) frame is on the stack — the driver's
// _Unwind_Backtrace must walk through us via .eh_frame.
XL_EXPORT int with_callback(int (*cb)(void *, int), void *user, int x) {
    return cb(user, x) + 1;
}
