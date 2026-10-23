/* Complete original MACore helper 0x38838..0x38aa4.
 * Raw fields retain original unsigned widths, including width+N wraparound.
 */
typedef unsigned long long u64;
typedef unsigned int u32;
static u32 r32(const unsigned char *p) {
  u32 v = 0; for (unsigned i=0; i<4; ++i) v |= (u32)p[i] << (8*i); return v;
}
static u64 r64(const unsigned char *p) {
  u64 v = 0; for (unsigned i=0; i<8; ++i) v |= (u64)p[i] << (8*i); return v;
}
static u64 contribution(u32 pixels, u32 rows, u32 scale, unsigned packed) {
  u64 bytes = (u64)pixels * scale;
  if (packed) bytes = (bytes + 7) >> 3;
  return (bytes + 1) * rows;
}
u64 mobilelogic_png_uncompressed_size(const unsigned char *context) {
  u32 height = r32(context + 0x1f4);
  u64 rowbytes = r64(context + 0x200);
  if ((rowbytes >> 15) || (height >> 15)) return 0xffffffffULL;
  if (!context[0x25c]) return (rowbytes + 1) * height;
  u32 width = r32(context + 0x1f0), depth = context[0x262];
  unsigned packed = depth <= 7;
  u32 scale = packed ? depth : depth >> 3;
  u64 total = 0;
  u32 n = width + 7;
  if (n >= 8) total += contribution(n >> 3, (height + 7) >> 3, scale, packed);
  n = width + 3;
  if (n >= 8) total += contribution(n >> 3, (height + 7) >> 3, scale, packed);
  if (n >= 4) total += contribution(n >> 2, (height + 3) >> 3, scale, packed);
  n = width + 1;
  if (n >= 4) total += contribution(n >> 2, (height + 3) >> 2, scale, packed);
  if (n >= 2) total += contribution(n >> 1, (height + 1) >> 2, scale, packed);
  if (width >= 2) total += contribution(width >> 1, (height + 1) >> 1, scale, packed);
  if (width) total += contribution(width, height >> 1, scale, packed);
  return total;
}
