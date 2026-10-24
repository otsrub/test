typedef unsigned int u32;
static u32 be32(const unsigned char*p){return ((u32)p[0]<<24)|((u32)p[1]<<16)|((u32)p[2]<<8)|p[3];}
u32 mobilelogic_png_get_int32(const unsigned char*p){u32 n=be32(p);return n==0x80000000U?0:n;}
u32 mobilelogic_png_get_uint32(const unsigned char*p){return be32(p);}
u32 mobilelogic_png_get_uint16(const unsigned char*p){return ((u32)p[0]<<8)|p[1];}
unsigned char *mobilelogic_png_save_uint32(unsigned char*p,u32 n){for(unsigned i=0;i<4;i++)p[i]=(unsigned char)(n>>(24-i*8));return p;}
unsigned char *mobilelogic_png_save_int32(unsigned char*p,u32 n){return mobilelogic_png_save_uint32(p,n);}
unsigned char *mobilelogic_png_save_uint16(unsigned char*p,u32 n){p[0]=(unsigned char)(n>>8);p[1]=(unsigned char)n;return p;}
