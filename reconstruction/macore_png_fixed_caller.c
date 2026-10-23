/* Restricted fixed-filter caller composition for original png_write_find_filter
 * at 0x3c144. Candidate source with a real unresolved original output callee.
 * It is NOT a complete filter-selection or compression implementation.
 * Precondition: exact mask 8,16,32,64,128; ordinary disjoint valid buffers,
 * rowbytes >= ceil(pixeldepth/8), and rowbytes below original overflow guard.
 */
#include <stdint.h>
extern unsigned char *mobilelogic_png_sub_transform(void *, uint64_t, uint32_t);
extern unsigned char *mobilelogic_png_up_transform(void *, uint64_t, uint32_t);
extern unsigned char *mobilelogic_png_average_transform(void *, uint64_t, uint32_t);
extern unsigned char *mobilelogic_png_paeth_transform(void *, uint64_t, uint32_t);

/* No substitute body is provided. Exact native identity is MACore 0x3848c. */
extern void mobilelogic_macore_png_write_IDAT_original_3848c(
    void *context, const unsigned char *row, uint64_t bytes, int flush);

void mobilelogic_png_fixed_find_filter(void *context, const void *row_info) {
  const unsigned char *info = row_info;
  uint64_t bytes;
  __builtin_memcpy(&bytes, info + 8, 8);
  uint32_t bpp = ((uint32_t)info[0x13] + 7u) >> 3;
  unsigned filter = ((const unsigned char *)context)[0x25e];
  unsigned char *output;
  switch (filter) {
  case 8: {
    uintptr_t pointer;
    __builtin_memcpy(&pointer, (const unsigned char *)context + 0x220, 8);
    output = (unsigned char *)pointer;
    break;
  }
  case 16: output = mobilelogic_png_sub_transform(context, bytes, bpp); break;
  case 32: output = mobilelogic_png_up_transform(context, bytes, bpp); break;
  case 64: output = mobilelogic_png_average_transform(context, bytes, bpp); break;
  case 128: output = mobilelogic_png_paeth_transform(context, bytes, bpp); break;
  default: __builtin_unreachable();
  }
  mobilelogic_macore_png_write_IDAT_original_3848c(context, output, bytes+1, 0);
  /* Native post-output row swapping, row completion, flushing and callbacks
   * remain outside the candidate's current source boundary. */
}
