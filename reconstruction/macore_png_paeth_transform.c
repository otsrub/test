/* MACore png_write_find_filter 0x3c144, fixed Paeth phase only.
 * Original phase entry 0x3c87c (filter mask 0x80), exit 0x3cde8.
 * No filter scoring/selection, compression or I/O implementation is claimed.
 */
#include <stdint.h>

static unsigned char *buffer(const void *context, unsigned offset) {
  uintptr_t pointer;
  __builtin_memcpy(&pointer, (const unsigned char *)context + offset, 8);
  return (unsigned char *)pointer;
}

unsigned char *mobilelogic_png_paeth_transform(void *context, uint64_t rowbytes,
                                               uint32_t bytes_per_pixel) {
  const unsigned char *previous = buffer(context, 0x218);
  const unsigned char *row = buffer(context, 0x220);
  unsigned char *output = buffer(context, 0x228);
  output[0] = 4;
  for (uint64_t i = 0; i < rowbytes; ++i) {
    int above = previous[i+1];
    int predictor = above;
    if (i >= bytes_per_pixel) {
      int left = row[i+1-bytes_per_pixel];
      int corner = previous[i+1-bytes_per_pixel];
      int a = above - corner;
      int b = left - corner;
      int c = a + b;
      if (a < 0) a = -a;
      if (b < 0) b = -b;
      if (c < 0) c = -c;
      /* Original comparison ties prefer left, then above, then corner. */
      predictor = a <= b && a <= c ? left : b <= c ? above : corner;
    }
    output[i+1] = (unsigned char)(row[i+1] - predictor);
  }
  return output;
}
