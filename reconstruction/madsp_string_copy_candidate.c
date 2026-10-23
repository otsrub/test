/* Original MADSP 0x41038..0x410b0. Real dependencies remain unresolved. */
#include <stdint.h>
extern void *madsp_new(uint64_t) __asm__("__Znwm");
extern void *memmove(void *,const void *,uint64_t);
extern _Noreturn void madsp_length_error_original_36e30(void);
static void write64(unsigned char*p,uint64_t x){for(unsigned i=0;i<8;i++)p[i]=(unsigned char)(x>>(8*i));}
void *madsp_string_copy_after_allocation(unsigned char*dst,const unsigned char*src,uint64_t length,uint64_t capacity,unsigned char*allocation){
 write64(dst+8,length);write64(dst+16,capacity|UINT64_C(0x8000000000000000));write64(dst,(uint64_t)(uintptr_t)allocation);
 return memmove(allocation,src,length+1);
}
void *madsp_string_copy(unsigned char*dst,const unsigned char*src,uint64_t length){
 if(length<=22){dst[23]=(unsigned char)length;return memmove(dst,src,length+1);}
 if(length>=UINT64_C(0x7ffffffffffffff8))madsp_length_error_original_36e30();
 uint64_t rounded=length|7,capacity=rounded==23?25:rounded+1;
 unsigned char*allocation=madsp_new(capacity);
 return madsp_string_copy_after_allocation(dst,src,length,capacity,allocation);
}
