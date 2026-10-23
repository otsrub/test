/* MACore png_write_find_filter 0x3c144: fixed-filter transform phases.
 * These are source phase ABIs, NOT complete png_write_find_filter replacements.
 * Context offsets come from original bytes; all buffers must be ordinary,
 * disjoint storage, rowbytes >= bytes_per_pixel, each with a header byte.
 */
#include <stdint.h>

static unsigned char *buffer(const void *context, unsigned offset) {
  uintptr_t pointer;
  __builtin_memcpy(&pointer, (const unsigned char *)context + offset, 8);
  return (unsigned char *)pointer;
}

/* Original entry cut 0x3c18c, exact filter=0x10, exit 0x3c4d4. */
unsigned char *mobilelogic_png_sub_transform(void *context, uint64_t rowbytes,
                                             uint32_t bytes_per_pixel) {
  const unsigned char *row = buffer(context, 0x220);
  unsigned char *output = buffer(context, 0x228);
  output[0] = 1;
  for (uint64_t i = 0; i < rowbytes; ++i)
    output[i+1] = (unsigned char)(row[i+1] -
        (i < bytes_per_pixel ? 0 : row[i+1-bytes_per_pixel]));
  return output;
}

/* Original entry cut 0x3c4d4, exact filter=0x20, exit 0x3c5c4. */
unsigned char *mobilelogic_png_up_transform(void *context, uint64_t rowbytes,
                                            uint32_t bytes_per_pixel) {
  (void)bytes_per_pixel;
  const unsigned char *previous = buffer(context, 0x218);
  const unsigned char *row = buffer(context, 0x220);
  unsigned char *output = buffer(context, 0x228);
  output[0] = 2;
  for (uint64_t i = 0; i < rowbytes; ++i)
    output[i+1] = (unsigned char)(row[i+1] - previous[i+1]);
  return output;
}

/* Original entry cut 0x3c5c4, exact filter=0x40, exit 0x3c87c. */
unsigned char *mobilelogic_png_average_transform(void *context, uint64_t rowbytes,
                                                 uint32_t bytes_per_pixel) {
  const unsigned char *previous = buffer(context, 0x218);
  const unsigned char *row = buffer(context, 0x220);
  unsigned char *output = buffer(context, 0x228);
  output[0] = 3;
  for (uint64_t i = 0; i < rowbytes; ++i) {
    unsigned left = i < bytes_per_pixel ? 0 : row[i+1-bytes_per_pixel];
    unsigned above = previous[i+1];
    output[i+1] = (unsigned char)(row[i+1] - ((left + above) >> 1));
  }
  return output;
}
