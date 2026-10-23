#include <stdint.h>
#include <string.h>

static uint32_t load_u32(const uint8_t *p) {
    uint32_t value;
    memcpy(&value, p, sizeof(value));
    return value;
}

static void store_u32(uint8_t *p, uint32_t value) {
    memcpy(p, &value, sizeof(value));
}

/*
 * Source for the no-callee part of MACore _png_write_find_filter after
 * _png_write_finish_row has returned (original 0x3ce1c..0x3ce58/0x3ce80).
 * A return value of one means the original reaches the real
 * _png_compress_IDAT(ctx, NULL, 0, 2) call at 0x3ce58.  Zero means it takes
 * the original epilogue without that call.  The native compression call,
 * row-finish callee and callback tail call are deliberately not replaced.
 */
uint32_t mobilelogic_macore_png_post_finish_pre_flush(uint8_t *context) {
    uint32_t completed = load_u32(context + 0x294u) + 1u;
    store_u32(context + 0x294u, completed);

    uint32_t final_row = load_u32(context + 0x290u) - 1u;
    if (final_row >= completed)
        return 0u;
    if (load_u32(context + 0x20cu) >= load_u32(context + 0x1f8u))
        return 0u;
    return 1u;
}
