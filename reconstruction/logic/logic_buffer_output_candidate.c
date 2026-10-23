/* Ordinary disjoint storage; fill leading-byte lengths <=4. Real memcpy,
 * memmove, memset and caller-provided growth callbacks remain dependencies. */
#include <stdint.h>
extern void *memcpy(void*,const void*,__SIZE_TYPE__);
extern void *memmove(void*,const void*,__SIZE_TYPE__);
extern void *memset(void*,int,__SIZE_TYPE__);
static uint64_t b_read(const unsigned char*p){uint64_t x=0;for(unsigned i=0;i<8;i++)x|=(uint64_t)p[i]<<(8*i);return x;}
static void b_write(unsigned char*p,uint64_t x){for(unsigned i=0;i<8;i++)p[i]=(unsigned char)(x>>(8*i));}
static int select_limit(unsigned char*out,uint64_t requested,uint64_t *selected){
 unsigned char *limit=(unsigned char*)(uintptr_t)b_read(out+32);
 *selected=requested;if(!limit)return 1;
 uint64_t end=b_read(limit),used=b_read(limit+8),available=end-used;
 *selected=available<requested?available:requested;b_write(limit+8,used+requested);
 return end>used && *selected!=0;
}
static void buffer_copy(unsigned char*out,const unsigned char *src,uint64_t remaining,unsigned move){
 for(;;){
  uint64_t pos=b_read(out+16),available=b_read(out+8)-pos;
  if(available<remaining+1){
   void(*grow)(unsigned char*,uint64_t)=(void(*)(unsigned char*,uint64_t))(uintptr_t)b_read(out+24);
   grow(out,remaining+2);pos=b_read(out+16);available=b_read(out+8)-pos;
  }
  uint64_t take=available<remaining?available:remaining;
  if(take){unsigned char*dst=(unsigned char*)(uintptr_t)(b_read(out)+pos);if(move)memmove(dst,src,take);else memcpy(dst,src,take);}
  b_write(out+16,b_read(out+16)+take);src+=take;
  if(remaining<=available)return;
  remaining-=take;
 }
}
static void buffer_set(unsigned char*out,uint64_t remaining,uint32_t fill){
 for(;;){
  uint64_t pos=b_read(out+16),available=b_read(out+8)-pos;
  if(available<remaining+1){
   void(*grow)(unsigned char*,uint64_t)=(void(*)(unsigned char*,uint64_t))(uintptr_t)b_read(out+24);
   grow(out,remaining+2);pos=b_read(out+16);available=b_read(out+8)-pos;
  }
  uint64_t take=available<remaining?available:remaining;
  if(take)memset((void*)(uintptr_t)(b_read(out)+pos),(int)fill,take);
  b_write(out+16,b_read(out+16)+take);
  if(remaining<=available)return;
  remaining-=take;
 }
}
uint64_t logic_buffer_padding(unsigned char*out,uint64_t count,uint64_t fill){
 unsigned n=0,c=(unsigned char)fill;for(unsigned bit=128;bit&&(c&bit);bit>>=1)n++;
 if(!n){uint64_t selected;if(select_limit(out,count,&selected))buffer_set(out,selected,(uint32_t)fill);}
 else{
  unsigned char bytes[4];for(unsigned i=0;i<4;i++)bytes[i]=(unsigned char)(fill>>(8*i));
  for(uint64_t i=0;i<count;i++){uint64_t selected;if(select_limit(out,n,&selected))buffer_copy(out,bytes,selected,0);}
 }
 return (uint64_t)(uintptr_t)out;
}
uint64_t logic_buffer_string(const unsigned char *text,uint64_t size,unsigned char*out,uint64_t first,uint64_t second,uint64_t visual){
 uint64_t delta=(uint64_t)((int64_t)first>>32)-visual;
 if((int64_t)delta<=0){uint64_t selected;if(select_limit(out,size,&selected))buffer_copy(out,text,selected,1);}
 else{
  unsigned alignment=(unsigned)first&7;uint64_t leading,trailing,fill=second>>32;
  if(alignment==1){leading=0;trailing=delta;}
  else if(alignment==0||alignment==3){leading=delta;trailing=0;}
  else{leading=delta>>1;trailing=delta-leading;}
  logic_buffer_padding(out,leading,fill);uint64_t selected;if(select_limit(out,size,&selected))buffer_copy(out,text,selected,1);logic_buffer_padding(out,trailing,fill);
 }
 return (uint64_t)(uintptr_t)out;
}
