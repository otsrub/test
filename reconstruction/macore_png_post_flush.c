#include <stdint.h>

static uint64_t load_u64(const uint8_t *p) {
    uint64_t value = 0;
    for (unsigned i = 0; i != 8; ++i)
        value |= (uint64_t)p[i] << (i * 8u);
    return value;
}

/*
 * Source for original MACore 0x3ce5c after the real flush compression call
 * returns.  It clears the row counter and exposes the optional callback target.
 * The caller must tail-call a nonzero result with x0=context, matching the
 * original.  This source contains no callback stub and never invokes it.
 */
uint64_t mobilelogic_macore_png_post_flush(uint8_t *context) {
    context[0x294u] = 0;
    context[0x295u] = 0;
    context[0x296u] = 0;
    context[0x297u] = 0;
    return load_u64(context + 0x288u);
}
