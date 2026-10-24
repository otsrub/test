typedef unsigned long long u64;typedef unsigned int u32;
static u64 r64(const unsigned char*p){u64 v=0;for(unsigned i=0;i<8;i++)v|=(u64)p[i]<<(i*8);return v;}
static u32 r32(const unsigned char*p){u32 v=0;for(unsigned i=0;i<4;i++)v|=(u32)p[i]<<(i*8);return v;}
static void w32(unsigned char*p,u32 v){for(unsigned i=0;i<4;i++)p[i]=(unsigned char)(v>>(i*8));}
static void be32(unsigned char*p,u32 v){for(unsigned i=0;i<4;i++)p[i]=(unsigned char)(v>>(24-i*8));}
static const char length_error[]="length exceeds PNG maximum";
static const char null_write_error[]="Call to NULL write function";
/* Descriptor of actual original return or first real callee. */
void mobilelogic_png_chunk_prefix(unsigned char*c,u32 tag,u64 data,u64 length,u64*out){
 out[0]=0;out[1]=0;out[2]=0;out[3]=0;
 if(!c)return;
 if(length>>31){out[0]=1;out[1]=0x46fcc;out[2]=(u64)c;out[3]=(u64)length_error;return;}
 w32(c+0x46c,0x22);unsigned char*h=(unsigned char*)out+64;be32(h,(u32)length);be32(h+4,tag);
 u64 callback=r64(c+0xf0);
 if(!callback){out[0]=1;out[1]=0x46fcc;out[2]=(u64)c;out[3]=(u64)null_write_error;return;}
 out[0]=2;out[1]=callback;out[2]=(u64)c;out[3]=8;
 (void)data;
}
#ifdef CHUNK_CANDIDATE
extern unsigned long crc32(unsigned long,const unsigned char*,unsigned int);
extern void png_error(void*,const char*) __attribute__((noreturn));
static void actual_write(unsigned char*c,const unsigned char*p,u64 n){
 u64 cb=r64(c+0xf0);if(!cb)png_error(c,null_write_error);
 ((void(*)(void*,const unsigned char*,u64))cb)(c,p,n);
}
static unsigned needs_crc(const unsigned char*c){u32 f=r32(c+0x128);return (c[0x213]&0x20)?((f&0x300)!=0x300):!(f&0x800);}
void mobilelogic_png_chunk_candidate(unsigned char*c,u32 tag,const unsigned char*data,u64 n){
 if(!c)return;if(n>>31)png_error(c,length_error);
 unsigned char header[8];w32(c+0x46c,0x22);be32(header,(u32)n);be32(header+4,tag);
 actual_write(c,header,8);w32(c+0x210,tag);
 u32 crc=(u32)crc32(0,0,0);w32(c+0x244,crc);
 if(needs_crc(c)){crc=(u32)crc32(crc,header+4,4);w32(c+0x244,crc);}
 w32(c+0x46c,0x42);
 if(data && n){actual_write(c,data,n);crc=r32(c+0x244);
  if(needs_crc(c)){u64 left=n;const unsigned char*p=data;do{u32 part=(u32)left;if(!part)part=0xffffffffU;crc=(u32)crc32(crc,p,part);p+=part;left-=part;}while(left);w32(c+0x244,crc);}
 }
 w32(c+0x46c,0x82);be32(header,crc);actual_write(c,header,4);
}
#endif
