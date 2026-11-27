#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>

static int check_cycle(const char *path, int cycle) {
    void *library = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (!library) {
        fprintf(stderr, "%s cycle %d: dlopen: %s\n", path, cycle, dlerror());
        return 1;
    }

    /* hello.c exports its existing main(void) when built as a shared object. */
    int (*hello)(void) = (int (*)(void))dlsym(library, "main");
    if (!hello) {
        fprintf(stderr, "%s cycle %d: dlsym did not find main\n", path, cycle);
        return 1;
    }
    int result = hello();
    if (result != 0) {
        fprintf(stderr, "%s cycle %d: main returned %d, expected 0\n", path, cycle, result);
        return 1;
    }
    if (dlclose(library) != 0) {
        fprintf(stderr, "%s cycle %d: dlclose: %s\n", path, cycle, dlerror());
        return 1;
    }

    library = dlopen(path, RTLD_NOW | RTLD_NOLOAD);
    if (library) {
        dlclose(library);
        fprintf(stderr, "%s cycle %d: library still loaded after dlclose\n", path, cycle);
        return 1;
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <shared-library>\n", argv[0]);
        return 2;
    }
    for (int cycle = 1; cycle <= 2; ++cycle) {
        if (check_cycle(argv[1], cycle) != 0) {
            return 1;
        }
    }
    return 0;
}
