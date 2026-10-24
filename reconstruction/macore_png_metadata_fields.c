/* Instruction-derived MACore PNG metadata routines. Standalone C ABI;
 * preserve original guard asymmetry and sequential aliased output writes.
 * Valid ordinary allocated memory only: no fault/MMIO/concurrent-access claim.
 */
#pragma STDC FENV_ACCESS ON
typedef unsigned long long u64; typedef unsigned int u32; typedef unsigned char u8;
static u32 r16(const u8*p){return (u32)p[0]|((u32)p[1]<<8);}
static u32 r32(const u8*p){u32 v=0;for(unsigned k=0;k<4;k++)v|=(u32)p[k]<<(8*k);return v;}
static u64 r64(const u8*p){u64 v=0;for(unsigned k=0;k<8;k++)v|=(u64)p[k]<<(8*k);return v;}
static void w32(u64 p,u32 v){for(unsigned k=0;k<4;k++)((u8*)p)[k]=(u8)(v>>(8*k));}
static void w64(u64 p,u64 v){for(unsigned k=0;k<8;k++)((u8*)p)[k]=(u8)(v>>(8*k));}
#define ARGS u64 c,u8*i,u64 a,u64 b,u64 d,u64 e,u64 f,u64 g,u64 h,u64 j,u64 k
#define READY(mask) (c&&i&&(r32(i+8)&(mask)))
u64 ml_png_PLTE(ARGS){if(!c||!i||!a||!(r32(i+8)&8))return 0;w64(a,r64(i+0x18));w32(b,r16(i+0x20));return 8;}
u64 ml_png_bKGD(ARGS){if(!c||!i||!a||!(r32(i+8)&32))return 0;w64(a,(u64)(i+0xca));return 32;}
u64 ml_png_hIST(ARGS){if(!c||!i||!a||!(r32(i+8)&64))return 0;w64(a,r64(i+0x100));return 64;}
u64 ml_png_sBIT(ARGS){if(!c||!i||!a||!(r32(i+8)&2))return 0;w64(a,(u64)(i+0xb0));return 2;}
u64 ml_png_tIME(ARGS){if(!c||!i||!a||!(r32(i+8)&512))return 0;w64(a,(u64)(i+0xa8));return 512;}
u64 ml_png_sRGB(ARGS){if(!c||!i||!a||!(r32(i+8)&2048))return 0;w32(a,r16(i+0x7c));return 2048;}
u64 ml_png_gAMA_fixed(ARGS){if(!c||!i||!a||!(r16(i+0x7e)&1))return 0;w32(a,r32(i+0x34));return 1;}
u64 ml_png_eXIf_1(ARGS){if(!c||!i||!b||!(r32(i+8)&65536))return 0;w32(a,r32(i+0xec));w64(b,r64(i+0xf0));return 65536;}
u64 ml_png_oFFs(ARGS){if(!c||!i||!d||!b||!a||!(r32(i+8)&256))return 0;u32 x=r32(i+0xd4),y=r32(i+0xd8);w32(a,x);w32(b,y);w32(d,i[0xdc]);return 256;}
u64 ml_png_iCCP(ARGS){if(!c||!i||!e||!d||!a||!(r32(i+8)&4096))return 0;u64 n=r64(i+0x80),p=r64(i+0x88);w64(a,n);w64(d,p);const u8*q=(const u8*)p;u32 length=((u32)q[0]<<24)|((u32)q[1]<<16)|((u32)q[2]<<8)|q[3];w32(e,length);if(b)w32(b,0);return 4096;}
u64 ml_png_sCAL_s(ARGS){if(!c||!i||!(i[9]&64))return 0;w32(a,i[0x14c]);u64 x=r64(i+0x150),y=r64(i+0x158);w64(b,x);w64(d,y);return 16384;}
u64 ml_png_cHRM_XYZ_fixed(ARGS){if(!c||!i||!(r16(i+0x7e)&2))return 0;if(a)w32(a,r32(i+0x58));if(b)w32(b,r32(i+0x5c));if(d)w32(d,r32(i+0x60));if(e)w32(e,r32(i+0x64));if(f)w32(f,r32(i+0x68));if(g)w32(g,r32(i+0x6c));if(h)w32(h,r32(i+0x70));if(j)w32(j,r32(i+0x74));if(k)w32(k,r32(i+0x78));return 4;}
u64 ml_png_cHRM_fixed(ARGS){if(!c||!i||!(r16(i+0x7e)&2))return 0;if(a)w32(a,r32(i+0x50));if(b)w32(b,r32(i+0x54));if(d)w32(d,r32(i+0x38));if(e)w32(e,r32(i+0x3c));if(f)w32(f,r32(i+0x40));if(g)w32(g,r32(i+0x44));if(h)w32(h,r32(i+0x48));if(j)w32(j,r32(i+0x4c));return 4;}
u64 ml_png_pCAL(ARGS){if(!c||!i||!a||!b||!d||!e||!f||!g||!h||!(r32(i+8)&1024))return 0;w64(a,r64(i+0x108));w32(b,r32(i+0x110));w32(d,r32(i+0x114));w32(e,i[0x128]);w32(f,i[0x129]);u64 x=r64(i+0x118),y=r64(i+0x120);w64(g,x);w64(h,y);return 1024;}
u64 ml_png_pHYs(ARGS){if(!c||!i||!(i[8]&128))return 0;u32 result=0;if(a){w32(a,r32(i+0xe0));result=128;}if(b){w32(b,r32(i+0xe4));result=128;}if(d){w32(d,i[0xe8]);result=128;}return result;}
u64 ml_png_tRNS(ARGS){if(!c||!i||!(i[8]&16))return 0;u32 result=0;if(i[0x25]==3){if(a){w64(a,r64(i+0xb8));result=16;}if(d)w64(d,(u64)(i+0xc0));}else{if(d){w64(d,(u64)(i+0xc0));result=16;}if(a)w64(a,0);}if(b){w32(b,r16(i+0x22));result=16;}return result;}
u64 ml_png_text(ARGS){u32 n=0;if(c&&i&&(int)r32(i+0x94)>=1){n=r32(i+0x94);if(a)w64(a,r64(i+0xa0));}if(b)w32(b,n);return n;}
u64 ml_png_x_pixels_per_meter(ARGS){return READY(128)&&i[0xe8]==1?r32(i+0xe0):0;}
u64 ml_png_y_pixels_per_meter(ARGS){return READY(128)&&i[0xe8]==1?r32(i+0xe4):0;}
u64 ml_png_pixels_per_meter(ARGS){if(!READY(128)||i[0xe8]!=1)return 0;u32 x=r32(i+0xe0),y=r32(i+0xe4);return x==y?x:0;}
u64 ml_png_x_offset_microns(ARGS){return READY(256)&&i[0xdc]==1?r32(i+0xd4):0;}
u64 ml_png_y_offset_microns(ARGS){return READY(256)&&i[0xdc]==1?r32(i+0xd8):0;}
u64 ml_png_x_offset_pixels(ARGS){return READY(256)&&i[0xdc]==0?r32(i+0xd4):0;}
u64 ml_png_y_offset_pixels(ARGS){return READY(256)&&i[0xdc]==0?r32(i+0xd8):0;}
/* Floating constants are exact original binary64 literals, not rounded decimal
 * reformulations. FP environment is part of the differential result. */
u64 ml_png_gAMA(ARGS){if(!c||!i||!a||!(r16(i+0x7e)&1))return 0;double v=(double)(int)r32(i+0x34)*0x1.4f8b588e368f1p-17;u64 bits;__builtin_memcpy(&bits,&v,8);w64(a,bits);return 1;}
float ml_png_pixel_aspect_ratio(ARGS){if(!READY(128))return 0;u32 x=r32(i+0xe0);if(!x)return 0;float y=(float)r32(i+0xe4);float xx=(float)x;return y/xx;}
float ml_png_x_offset_inches(ARGS){if(!READY(256)||i[0xdc]!=1)return 0;return (float)((double)(int)r32(i+0xd4)*0x1.4a426e648c9c8p-15);}
float ml_png_y_offset_inches(ARGS){if(!READY(256)||i[0xdc]!=1)return 0;return (float)((double)(int)r32(i+0xd8)*0x1.4a426e648c9c8p-15);}
