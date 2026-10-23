#include <stdint.h>

static uint32_t load_u32(const uint8_t *p) {
    return (uint32_t)p[0]
        | ((uint32_t)p[1] << 8)
        | ((uint32_t)p[2] << 16)
        | ((uint32_t)p[3] << 24);
}

static void store_u32(uint8_t *p, uint32_t value) {
    p[0] = (uint8_t)value;
    p[1] = (uint8_t)(value >> 8);
    p[2] = (uint8_t)(value >> 16);
    p[3] = (uint8_t)(value >> 24);
}

/*
 * Recovered prefix of MACore _png_write_finish_row, original
 * 0x3b9a4..0x3b9c8/0x3848c.  Result 0 is the original early return, result 1
 * is the real _png_compress_IDAT(ctx, NULL, 0, 4) tail-call path, and result 2
 * is the unresolved interlace continuation beginning at 0x3b9c8.
 */
uint32_t mobilelogic_macore_png_finish_row_prefix(uint8_t *context) {
    uint32_t row = load_u32(context + 0x20cu) + 1u;
    store_u32(context + 0x20cu, row);
    if (row < load_u32(context + 0x1f8u))
        return 0u;
    if (context[0x25cu] == 0)
        return 1u;
    return 2u;
}
