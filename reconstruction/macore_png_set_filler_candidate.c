/* Complete source candidate; real native warning/error functions remain external.
 * Compilation is not runtime closure or accepted complete-function evidence. */
typedef unsigned char u8;typedef unsigned int u32;
extern void png_warning(u8*,const char*);
extern void png_error(u8*,const char*) __attribute__((noreturn));
static u32 r32(const u8*p){u32 v=0;for(unsigned k=0;k<4;k++)v|=(u32)p[k]<<(8*k);return v;}
static void w32(u8*p,u32 v){for(unsigned k=0;k<4;k++)p[k]=(u8)(v>>(8*k));}
void ml_png_set_filler_candidate(u8*p,u32 filler,int location){
 if(!p)return;
 if(p[0x125]&0x80){p[0x26a]=(u8)filler;p[0x26b]=(u8)(filler>>8);}
 else if(p[0x25f]==2)p[0x264]=4;
 else if(p[0x25f]==0&&p[0x260]>=8)p[0x264]=2;
 else {
  const char*message=p[0x25f]==0?"png_set_filler is invalid for low bit depth gray output":"png_set_filler: inappropriate color type";
  if(p[0x12a]&0x40){png_warning(p,message);return;}
  png_error(p,message);
 }
 w32(p+0x12c,r32(p+0x12c)|0x8000);
 u32 flags=r32(p+0x128);w32(p+0x128,location==1?flags|0x80:flags&0xffffff7f);
}
