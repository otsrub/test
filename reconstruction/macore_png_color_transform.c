/* Real instruction-derived MACore functions. Public memory may alias;
 * sequential field loads and output writes preserve original ordering.
 * Ordinary mapped memory, no fault/MMIO/race equivalence claim. */
#pragma STDC FENV_ACCESS ON
typedef unsigned long long u64;typedef unsigned int u32;typedef unsigned char u8;
static u32 r16(const u8*p){return (u32)p[0]|((u32)p[1]<<8);}
static u32 r32(const u8*p){u32 v=0;for(unsigned n=0;n<4;n++)v|=(u32)p[n]<<(n*8);return v;}
static void w32(u8*p,u32 v){for(unsigned n=0;n<4;n++)p[n]=(u8)(v>>(n*8));}
static void wd(u64 p,double v){u64 b;__builtin_memcpy(&b,&v,8);for(unsigned n=0;n<8;n++)((u8*)p)[n]=(u8)(b>>(n*8));}
#define ARGS u64 c,u8*i,u64 a,u64 b,u64 d,u64 e,u64 f,u64 g,u64 h,u64 j,u64 k
#define OUT(p,o) if(p)wd(p,(double)(int)r32(i+(o))*0x1.4f8b588e368f1p-17)
u64 ml_png_cHRM(ARGS){if(!c||!i||!(r16(i+0x7e)&2))return 0;OUT(a,0x50);OUT(b,0x54);OUT(d,0x38);OUT(e,0x3c);OUT(f,0x40);OUT(g,0x44);OUT(h,0x48);OUT(j,0x4c);return 4;}
u64 ml_png_cHRM_XYZ(ARGS){if(!c||!i||!(r16(i+0x7e)&2))return 0;OUT(a,0x58);OUT(b,0x5c);OUT(d,0x60);OUT(e,0x64);OUT(f,0x68);OUT(g,0x6c);OUT(h,0x70);OUT(j,0x74);OUT(k,0x78);return 4;}
/* These setters have void result ABI except interlace_handling. */
void ml_png_set_bgr(u8*p){if(p)w32(p+0x12c,r32(p+0x12c)|1);}
void ml_png_set_swap(u8*p){if(p&&p[0x260]==16)w32(p+0x12c,r32(p+0x12c)|16);}
void ml_png_set_packing(u8*p){if(p&&p[0x260]<8){w32(p+0x12c,r32(p+0x12c)|4);p[0x261]=8;}}
void ml_png_set_packswap(u8*p){if(p&&p[0x260]<8)w32(p+0x12c,r32(p+0x12c)|0x10000);}
void ml_png_set_shift(u8*p,const u8*q){if(p){w32(p+0x12c,r32(p+0x12c)|8);u32 first=r32(q);w32(p+0x2d5,first);p[0x2d9]=q[4];}}
void ml_png_set_invert_mono(u8*p){if(p)w32(p+0x12c,r32(p+0x12c)|0x20);}
void ml_png_set_swap_alpha(u8*p){if(p)w32(p+0x12c,r32(p+0x12c)|0x20000);}
void ml_png_set_invert_alpha(u8*p){if(p)w32(p+0x12c,r32(p+0x12c)|0x80000);}
u64 ml_png_set_interlace_handling(u8*p){if(p&&p[0x25c]){w32(p+0x12c,r32(p+0x12c)|2);return 7;}return 1;}
