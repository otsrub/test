#include <stdint.h>

static uint64_t load_u64(const uint8_t *p) {
    uint64_t value = 0;
    for (unsigned i = 0; i != 8; ++i)
        value |= (uint64_t)p[i] << (i * 8u);
    return value;
}

static void store_u64(uint8_t *p, uint64_t value) {
    for (unsigned i = 0; i != 8; ++i)
        p[i] = (uint8_t)(value >> (i * 8u));
}

/*
 * Original MACore _png_write_find_filter phase 0x3ce00..0x3ce18 after the
 * first real _png_compress_IDAT call returns.  The source swaps previous and
 * current row pointers only when a previous-row pointer exists.  The real
 * _png_write_finish_row dependency at 0x3b9a4 is not replaced.
 */
void mobilelogic_macore_png_row_swap(uint8_t *context) {
    uint64_t previous = load_u64(context + 0x218u);
    if (previous != 0) {
        uint64_t current = load_u64(context + 0x220u);
        store_u64(context + 0x218u, current);
        store_u64(context + 0x220u, previous);
    }
}
