/* Original-byte-derived MACore PNG leaf routines. No native callees.
 * Preserve FP environment, saturating conversion and sequential row writes.
 * Ordinary allocated memory, no fault/MMIO/race equivalence assertion. */
#pragma STDC FENV_ACCESS ON
typedef unsigned char u8; typedef unsigned int u32; typedef unsigned long long u64;
static u32 r32(const u8*p){u32 x=0;for(unsigned k=0;k<4;k++)x|=(u32)p[k]<<(8*k);return x;}
static u64 r64(const u8*p){u64 x=0;for(unsigned k=0;k<8;k++)x|=(u64)p[k]<<(8*k);return x;}
/* fcvtms executes even when the subsequent range check rejects its result;
 * replacing this with a guarded C cast would lose original FPSR behavior. */
static u32 rounded(double x){double f=__builtin_floor(x);int value;__asm__ volatile("fcvtms %w0, %d1":"=r"(value):"w"(x));return f>=-2147483648.0&&f<=2147483647.0?(u32)value:0;}
u32 ml_png_pixel_aspect_ratio_fixed(u64 c,const u8*i){if(!c||!i||!(i[8]&128))return 0;int x=(int)r32(i+0xe0);if(x<=0)return 0;int y=(int)r32(i+0xe4);if(y<1)return 0;double v=(double)y*100000.0;v=v/(double)x;v=v+0.5;return rounded(v);}
static u32 density(u64 c,const u8*i,unsigned axis,unsigned equal){if(!c||!i||!(i[8]&128)||i[0xe8]!=1)return 0;u32 x=r32(i+axis);if(equal&&x!=r32(i+0xe4))return 0;if((int)x<1)return 0;double v=(double)x*127.0;v=v/5000.0;v=v+0.5;return rounded(v);}
u32 ml_png_pixels_per_inch(u64 c,const u8*i){return density(c,i,0xe0,1);}
u32 ml_png_x_pixels_per_inch(u64 c,const u8*i){return density(c,i,0xe0,0);}
u32 ml_png_y_pixels_per_inch(u64 c,const u8*i){return density(c,i,0xe4,0);}
void ml_png_do_packswap(const u8*info,u8*row){unsigned d=info[0x11];if(d>7)return;u64 n=r64(info+8);if(d!=1&&d!=2&&d!=4)return;if((long long)n<1)return;for(u64 k=0;k<n;k++){unsigned v=row[k];if(d==1){v=((v&0x55)<<1)|((v>>1)&0x55);v=((v&0x33)<<2)|((v>>2)&0x33);v=(v<<4)|(v>>4);}else if(d==2){v=((v&0x33)<<2)|((v>>2)&0x33);v=(v<<4)|(v>>4);}else v=(v<<4)|(v>>4);row[k]=(u8)v;}}
