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
/* Parameters selected from actual original bytes, not a replacement zlib. */
static void parameters(const unsigned char *c,u32 owner,u64 length,u32 p[5]){
 unsigned base=owner==0x49444154U?0x1b4:0x1c8;
 for(unsigned i=0;i<4;i++)p[i]=r32(c+base+4*i);
 if(owner!=0x49444154U)p[4]=r32(c+0x1d8);
 else p[4]=(r32(c+0x128)&1)?r32(c+0x1c4):(c[0x25e]!=8);
 if(length<=16384){u32 window=1U<<((p[2]-1U)&31U);u64 needed=length+262;
  if(needed<=(u64)window){do{window>>=1;p[2]--;}while(window>=(u32)needed);}
 }
}
/* Descriptor at first REAL call; no warning/zlib callbacks run here.
 result[0]kind,[1]target,[2..9]actual ABI arguments; warning bytes at+80.
 */
void mobilelogic_png_claim_prefix(unsigned char *c,u32 owner,u64 length,u64 *result){
 for(unsigned i=0;i<10;i++)result[i]=0;
 u32 busy=r32(c+0x130);
 if(busy){result[0]=0;result[1]=0x47204;result[2]=(u64)c;
  unsigned char *s=(unsigned char*)result+80;
  for(unsigned i=0;i<4;i++){s[i]=(unsigned char)(owner>>(24-8*i));s[6+i]=(unsigned char)(busy>>(24-8*i));}
  s[4]=':';s[5]=' ';for(unsigned i=0;i<12;i++)s[10+i]=warning_constant[i];s[22]='a';s[23]='m';s[24]=0;return;
 }
 u32 p[5];parameters(c,owner,length,p);u32 flags=r32(c+0x128);
 if(flags&2){unsigned equal=1;for(unsigned i=0;i<5;i++)if(r32(c+0x1dc+4*i)!=p[i])equal=0;
  if(!equal){result[0]=1;result[1]=0x104a88;result[2]=(u64)(c+0x138);return;}
 }
 w64(c+0x138,0);w32(c+0x140,0);w64(c+0x150,0);w32(c+0x158,0);
 result[2]=(u64)(c+0x138);
 if(flags&2){result[0]=2;result[1]=0x104aac;}
 else{result[0]=3;result[1]=0x104a94;for(unsigned i=0;i<5;i++)result[3+i]=p[i];result[8]=(u64)literal_12de59;result[9]=0x70;}
}
#ifdef CLAIM_CANDIDATE
extern int deflateEnd(void*);
extern int deflateReset(void*);
extern int deflateInit2_(void*,int,int,int,int,int,const char*,int);
extern void png_warning(void*,const char*);
int mobilelogic_png_claim_candidate(unsigned char *c,u32 owner,u64 length){
 u32 busy=r32(c+0x130);
 if(busy){char s[25];for(unsigned i=0;i<4;i++){s[i]=(char)(owner>>(24-8*i));s[6+i]=(char)(busy>>(24-8*i));}
  s[4]=':';s[5]=' ';for(unsigned i=0;i<12;i++)s[10+i]=(char)warning_constant[i];s[22]='a';s[23]='m';s[24]=0;
  png_warning(c,s);if(r32(c+0x130)==0x49444154U){w64(c+0x168,(u64)literal_1264d8);return -2;}w32(c+0x130,0);
 }
 u32 p[5];parameters(c,owner,length,p);u32 flags=r32(c+0x128);
 if(flags&2){unsigned equal=1;for(unsigned i=0;i<5;i++)if(r32(c+0x1dc+4*i)!=p[i])equal=0;
  if(!equal){if(deflateEnd(c+0x138))png_warning(c,literal_1264e7);flags=r32(c+0x128)&~2U;w32(c+0x128,flags);}
 }
 w64(c+0x138,0);w32(c+0x140,0);w64(c+0x150,0);w32(c+0x158,0);
 int status;
 if(flags&2)status=deflateReset(c+0x138);
 else{status=deflateInit2_(c+0x138,(int)p[0],(int)p[1],(int)p[2],(int)p[3],(int)p[4],literal_12de59,112);
  if(!status)w32(c+0x128,r32(c+0x128)|2U);}
 if(!status)w32(c+0x130,owner);else mobilelogic_png_zstream_error(c,(u32)status);
 return status;
}
#endif
