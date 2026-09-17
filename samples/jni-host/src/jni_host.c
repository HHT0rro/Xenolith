/* JNI-shaped host sample (JavaShroud adaptation, S1). Mirrors the Qp native
 * host contract that the packer must support:
 *   - a JVM ABI entry point (JNI_OnLoad) that must stay native and loadable;
 *   - `.jsms` / `.jsmk` / `.jsmd` measurement slots that must survive packing
 *     byte-identical (the runtime reads commitments through volatile loads);
 *   - one pure 2xu32 arithmetic leaf that is a real VM target (W1 shape:
 *     wrapping ^ + - and one unsigned compare, no CRT calls).
 * Frozen at -O1 / /O1.
 */

typedef unsigned long DWORD;
typedef void *HINSTANCE;
typedef void *LPVOID;

#ifdef _MSC_VER
#define XL_EXPORT __declspec(dllexport)
#define XL_WINAPI __stdcall
#pragma section(".jsms", read)
#pragma section(".jsmk", read)
#pragma section(".jsmd", read)
#define JS_SECTION __declspec(allocate(".jsms"))
#define JK_SECTION __declspec(allocate(".jsmk"))
#define JD_SECTION __declspec(allocate(".jsmd"))
#else
#define XL_EXPORT __attribute__((visibility("default")))
#define XL_WINAPI
#define JS_SECTION __attribute__((section(".jsms")))
#define JK_SECTION __attribute__((section(".jsmk")))
#define JD_SECTION __attribute__((section(".jsmd")))
#endif

#define JNI_VERSION_1_8 0x00010008

/* JavaShroud JSIM measurement slot: magic + version + zeroed commitment. */
JS_SECTION
const unsigned char js_measurement[40] = {
    'J', 'S', 'I', 'M', 0x01, 'v', '6', '\0',
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
};

/* Shard-key mask row (pre-mask shape); must stay byte-identical on disk. */
JK_SECTION
const unsigned char js_shard_key[32] = {
    'J', 'S', 'M', 'K', 0x01, 'k', '1', '\0',
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
};

/* Dialect mask row; must stay byte-identical on disk. */
JD_SECTION
const unsigned char js_dialect[32] = {
    'J', 'S', 'M', 'D', 0x01, 'd', '1', '\0',
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
    0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
    0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
};

XL_EXPORT
unsigned jh_leaf_mix(unsigned a, unsigned b)
{
    unsigned t = a ^ b;
    t += 0x9E3779B9u;
    if (t > 0x00010000u) {
        return t - b;
    }
    return t + b;
}

XL_EXPORT
int XL_WINAPI JNI_OnLoad(void *vm, void *reserved)
{
    (void)vm;
    (void)reserved;
    return JNI_VERSION_1_8;
}
