/* Compose the verified entry phase with the recovered complete native helper.
 * The next unresolved call at 0x38aa4 is recorded, not simulated.
 */
#define r32 png_prefix_r32
#define r64 png_prefix_r64
#include "macore_png_compress_prefix.c"
#undef r32
#undef r64
#include "macore_png_uncompressed_size.c"

void mobilelogic_png_compress_composed(unsigned char *context, u64 input,
                                      u64 length, u32 flush, u64 *result) {
  mobilelogic_png_compress_prefix(context, input, length, flush, result);
  result[4] = 0;
  if (result[0] == 5) {
    result[1] = 0x38aa4;
    result[3] = 0x49444154U;
    result[4] = mobilelogic_png_uncompressed_size(context);
  }
}
