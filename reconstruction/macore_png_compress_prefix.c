/* Original MACore png_compress_IDAT entry through its first real call.
 * The descriptor records native call boundaries; it executes no callees.
 */
typedef unsigned long long u64;
typedef unsigned int u32;
static u64 r64(const unsigned char *p) {
  u64 v = 0; for (unsigned i = 0; i < 8; ++i) v |= (u64)p[i] << (8*i); return v;
}
static u32 r32(const unsigned char *p) {
  u32 v = 0; for (unsigned i = 0; i < 4; ++i) v |= (u32)p[i] << (8*i); return v;
}
static void w64(unsigned char *p, u64 v) {
  for (unsigned i = 0; i < 8; ++i) p[i] = (unsigned char)(v >> (8*i));
}
static void w32(unsigned char *p, u32 v) {
  for (unsigned i = 0; i < 4; ++i) p[i] = (unsigned char)(v >> (8*i));
}
void mobilelogic_png_compress_prefix(unsigned char *context, u64 input,
                                    u64 length, u32 flush, u64 *result) {
  u64 kind, target, arg0, arg1 = 0;
  if (r32(context + 0x130) == 0x49444154U) {
    w64(context + 0x138, input);
    w32(context + 0x140, (u32)(length < 0xffffffffULL ? length : 0xffffffffULL));
    kind = 0; target = 0x104a7c; arg0 = (u64)(context + 0x138);
    arg1 = length >> 32 ? 0 : flush;
  } else {
    u64 holder = r64(context + 0x1a8);
    if (!holder) {
      u64 allocation = (u64)r32(context + 0x1b0) + 8;
      target = r64(context + 0x3e8);
      if (target) { kind = 4; arg0 = (u64)context; arg1 = allocation; }
      else { kind = 3; target = 0x104ddc; arg0 = allocation; }
    } else {
      u64 node = r64((const unsigned char *)holder);
      if (node) {
        w64((unsigned char *)holder, 0);
        /* Original next-link read occurs before the free call. Ordinary
         * stable valid memory is the tested domain; no fault/race claim. */
        (void)r64((const unsigned char *)node);
        target = r64(context + 0x3f0);
        if (target) { kind = 2; arg0 = (u64)context; arg1 = node; }
        else { kind = 1; target = 0x104c14; arg0 = node; }
      } else { kind = 5; target = 0x38838; arg0 = (u64)context; }
    }
  }
  result[0] = kind; result[1] = target; result[2] = arg0; result[3] = arg1;
}
