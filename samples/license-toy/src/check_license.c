/* W1 truth sample. Frozen at -O1 / /O1.
 * Only wrapping ^ + - and one unsigned compare. No CRT calls.
 */

typedef int BOOL;
typedef void *HINSTANCE;
typedef unsigned long DWORD;
typedef void *LPVOID;

#ifdef _MSC_VER
#define XL_EXPORT __declspec(dllexport)
#define XL_WINAPI __stdcall
#else
#define XL_EXPORT __attribute__((visibility("default")))
#define XL_WINAPI
#endif

XL_EXPORT
unsigned check_license(unsigned x, unsigned y)
{
    unsigned t = x ^ y;
    t += 0x9E3779B9u;
    if (t > 0x00010000u) {
        return t - y;
    }
    return t + y;
}

XL_EXPORT
BOOL XL_WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID reserved)
{
    (void)h;
    (void)reason;
    (void)reserved;
    return 1;
}
