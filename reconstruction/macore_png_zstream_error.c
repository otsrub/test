typedef unsigned long long u64; typedef unsigned int u32;
static u32 r32(const unsigned char *p){u32 v=0;for(unsigned i=0;i<4;i++)v|=(u32)p[i]<<(8*i);return v;}
static u64 r64(const unsigned char *p){u64 v=0;for(unsigned i=0;i<8;i++)v|=(u64)p[i]<<(8*i);return v;}
static void w32(unsigned char *p,u32 v){for(unsigned i=0;i<4;i++)p[i]=(unsigned char)(v>>(8*i));}
static void w64(unsigned char *p,u64 v){for(unsigned i=0;i<8;i++)p[i]=(unsigned char)(v>>(8*i));}
static const char literal_12521e[]={117,110,101,120,112,101,99,116,101,100,32,122,108,105,98,32,114,101,116,117,114,110,32,99,111,100,101,0};
static const char literal_12523a[]={117,110,101,120,112,101,99,116,101,100,32,101,110,100,32,111,102,32,76,90,32,115,116,114,101,97,109,0};
static const char literal_125256[]={109,105,115,115,105,110,103,32,76,90,32,100,105,99,116,105,111,110,97,114,121,0};
static const char literal_12526c[]={122,108,105,98,32,73,79,32,101,114,114,111,114,0};
static const char literal_12527a[]={98,97,100,32,112,97,114,97,109,101,116,101,114,115,32,116,111,32,122,108,105,98,0};
static const char literal_125291[]={100,97,109,97,103,101,100,32,76,90,32,115,116,114,101,97,109,0};
static const char literal_1252a3[]={117,110,115,117,112,112,111,114,116,101,100,32,122,108,105,98,32,118,101,114,115,105,111,110,0};
static const char literal_1252bc[]={117,110,101,120,112,101,99,116,101,100,32,122,108,105,98,32,114,101,116,117,114,110,0};
static const char literal_1264d8[]={105,110,32,117,115,101,32,98,121,32,73,68,65,84,0};
static const char literal_1264e7[]={100,101,102,108,97,116,101,69,110,100,32,102,97,105,108,101,100,32,40,105,103,110,111,114,101,100,41,0};
static const char literal_12dac8[]={116,114,117,110,99,97,116,101,100,0};
static const char literal_12db0b[]={105,110,115,117,102,102,105,99,105,101,110,116,32,109,101,109,111,114,121,0};
static const char literal_12de59[]={49,46,50,46,49,50,0};
static const char *const error_table[10]={literal_1252bc,literal_1252a3,literal_12dac8,literal_12db0b,literal_125291,literal_12527a,literal_12526c,literal_12521e,literal_12523a,literal_125256};
static const unsigned char warning_constant[12]={32,117,115,105,110,103,32,122,115,116,114,101};
/* Complete original MACore0x2dd78..0x2ddb4, retaining existing message. */
unsigned char *mobilelogic_png_zstream_error(unsigned char *ctx,u32 code){
 if(!r64(ctx+0x168)) {u32 index=code+7U;w64(ctx+0x168,(u64)(index<=9?error_table[index]:literal_12521e));}
 return ctx;
}
