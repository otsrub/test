/* Original MADSP DevDaisyTrigger::PurgeDuplicates, 0xb519cc..0xb51ab0.
 * Ordinary disjoint object/provider/36-byte-record storage; no concurrent mutation.
 * Arithmetic and ordering deliberately retain AArch64 wraparound semantics. */
#include <stdint.h>
static uint64_t read64(const unsigned char*p){uint64_t v=0;for(unsigned i=0;i<8;i++)v|=(uint64_t)p[i]<<(8*i);return v;}
static void write64(unsigned char*p,uint64_t v){for(unsigned i=0;i<8;i++)p[i]=(unsigned char)(v>>(8*i));}
static int signed_less(uint64_t a,uint64_t b){return (a^UINT64_C(0x8000000000000000))<(b^UINT64_C(0x8000000000000000));}
static int duplicate(const unsigned char*record,const unsigned char*object,uint64_t threshold){uint64_t delta=read64(record)-read64(object+0x80);if(delta>>63)delta=0-delta;return signed_less(delta,threshold);}
unsigned char *madsp_purge_duplicates(unsigned char*object){
 unsigned char*first=(unsigned char*)(uintptr_t)read64(object+0x90);
 unsigned char*last=(unsigned char*)(uintptr_t)read64(object+0x98);
 if(first==last)return object;
 const unsigned char*provider=(const unsigned char*)(uintptr_t)read64(object+0x88);
 uint64_t threshold=read64(provider+0x60);
 unsigned char*dst=first;
 while(dst!=last&&!duplicate(dst,object,threshold))dst+=36;
 if(dst==last)return object;
 for(unsigned char*src=dst+36;src!=last;src+=36)if(!duplicate(src,object,threshold)){for(unsigned i=0;i<36;i++)dst[i]=src[i];dst+=36;}
 write64(object+0x98,(uint64_t)(uintptr_t)dst);
 return object;
}
