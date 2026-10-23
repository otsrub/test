#include <stdint.h>

typedef struct {
    uint64_t outcome;
    uint64_t x0;
    uint64_t x1;
    uint64_t x2;
    uint64_t x3;
} mobilelogic_png_tail;

static uint32_t load_u32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8)
        | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static uint64_t load_u64(const uint8_t *p) {
    return (uint64_t)load_u32(p) | ((uint64_t)load_u32(p + 4) << 32);
}
static void store_u32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

/*
 * Composed source reconstruction of MACore _png_write_finish_row,
 * 0x3b9a4..0x3bd14. External tail callees are not replaced: outcome 1
 * describes the exact _png_compress_IDAT register state and outcome 2 the
 * exact _bzero register state. Outcome 0 is the function's complete return.
 */
void mobilelogic_macore_png_finish_row_composed(
    uint8_t *context, mobilelogic_png_tail *tail) {
    static const uint8_t y_start[7] = {0, 0, 4, 0, 2, 0, 1};
    static const uint8_t y_step[7]  = {8, 8, 8, 4, 4, 2, 2};
    static const uint8_t x_start[7] = {0, 4, 0, 2, 0, 1, 0};
    static const uint8_t x_step[7]  = {8, 8, 4, 4, 2, 2, 1};
    uint32_t row = load_u32(context + 0x20c) + 1u;
    store_u32(context + 0x20c, row);
    if (row < load_u32(context + 0x1f8))
        goto complete_return;
    if (context[0x25c] == 0u)
        goto compress;

    store_u32(context + 0x20c, 0u);
    {
        uint8_t pass = (uint8_t)(context[0x25d] + 1u);
        if ((context[0x12c] & 2u) != 0u) {
            context[0x25d] = pass;
            if (pass > 6u)
                goto compress;
        } else {
            uint32_t width = load_u32(context + 0x1f0);
            uint32_t height = load_u32(context + 0x1f4);
            for (;;) {
                if (pass > 6u) {
                    context[0x25d] = pass;
                    goto compress;
                }
                uint32_t xn = width + (uint32_t)x_step[pass]
                    - (uint32_t)x_start[pass] - 1u;
                uint32_t yn = height + (uint32_t)y_step[pass]
                    - (uint32_t)y_start[pass] - 1u;
                store_u32(context + 0x1fc, xn / (uint32_t)x_step[pass]);
                store_u32(context + 0x1f8, yn / (uint32_t)y_step[pass]);
                if (xn >= (uint32_t)x_step[pass]
                        && yn >= (uint32_t)y_step[pass]) {
                    context[0x25d] = pass;
                    break;
                }
                pass = (uint8_t)(pass + 1u);
            }
        }
    }

    {
        uint64_t previous = load_u64(context + 0x218);
        if (previous == 0u)
            goto complete_return;
        uint32_t bits = (uint32_t)context[0x261]
            * (uint32_t)context[0x264];
        uint32_t width = load_u32(context + 0x1f0);
        uint64_t bytes = bits < 8u
            ? (((uint64_t)width * (uint64_t)bits + 7u) >> 3)
            : ((uint64_t)width * (uint64_t)(bits >> 3));
        tail->outcome = 2u;
        tail->x0 = previous;
        tail->x1 = bytes + 1u;
        tail->x2 = 0u;
        tail->x3 = 0u;
        return;
    }

complete_return:
    tail->outcome = 0u;
    tail->x0 = (uint64_t)(uintptr_t)context;
    tail->x1 = 0u;
    tail->x2 = 0u;
    tail->x3 = 0u;
    return;

compress:
    tail->outcome = 1u;
    tail->x0 = (uint64_t)(uintptr_t)context;
    tail->x1 = 0u;
    tail->x2 = 0u;
    tail->x3 = 4u;
}
