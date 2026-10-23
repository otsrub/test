/* Original MADSP DevDaisyTrigger::PurgeStaleTransients, 0xb51ab0..0xb51ba8.
 * Native saturating float conversion and FPSR invalid flag preserved. No aliases/concurrency. */
#include <stdint.h>
static uint64_t read64(const unsigned char*p){uint64_t v=0;for(unsigned i=0;i<8;i++)v|=(uint64_t)p[i]<<(8*i);return v;}
static uint32_t read32(const unsigned char*p){uint32_t v=0;for(unsigned i=0;i<4;i++)v|=(uint32_t)p[i]<<(8*i);return v;}
static void write64(unsigned char*p,uint64_t v){for(unsigned i=0;i<8;i++)p[i]=(unsigned char)(v>>(8*i));}
static int signed_greater(uint64_t a,uint64_t b){return (a^UINT64_C(0x8000000000000000))>(b^UINT64_C(0x8000000000000000));}
/* C has undefined float-to-int behavior outside range; recover ARM saturation
 * explicitly and update the architectural sticky invalid flag for these cases. */
static uint64_t to_int64_native(float value){
 union{float value;uint32_t bits;}v;v.value=value;uint32_t magnitude=v.bits&0x7fffffff;
 if(magnitude<0x5f000000)return (uint64_t)(int64_t)value;
 if(v.bits==0xdf000000)return UINT64_C(0x8000000000000000);
 uint64_t fpsr;__asm__ volatile("mrs %0, fpsr":"=r"(fpsr));fpsr|=1;__asm__ volatile("msr fpsr, %0"::"r"(fpsr));
 if(magnitude>0x7f800000)return 0;
 return v.bits>>31?UINT64_C(0x8000000000000000):UINT64_C(0x7fffffffffffffff);
}
static int stale(const unsigned char*r,uint64_t now,uint64_t limit){uint32_t d=read32(r+28);uint64_t duration=d;if(d>>31)duration|=UINT64_C(0xffffffff00000000);return signed_greater(now-read64(r)+duration,limit);}
unsigned char *madsp_purge_stale(unsigned char*object){
 unsigned char*dst=(unsigned char*)(uintptr_t)read64(object+0x90);
 unsigned char*last=(unsigned char*)(uintptr_t)read64(object+0x98);
 if(dst==last)return object;
 const unsigned char*provider=(const unsigned char*)(uintptr_t)read64(object+8);
 uint64_t now=read64(provider+0x48);union{uint32_t bits;float value;}rate;rate.bits=read32(provider+0x24);
 float half=rate.value*0.5f;uint64_t limit=to_int64_native(half);
 while(dst!=last&&!stale(dst,now,limit))dst+=36;
 if(dst==last)return object;
 for(unsigned char*src=dst+36;src!=last;src+=36)if(!stale(src,now,limit)){for(unsigned i=0;i<36;i++)dst[i]=src[i];dst+=36;}
 write64(object+0x98,(uint64_t)(uintptr_t)dst);return object;
}
