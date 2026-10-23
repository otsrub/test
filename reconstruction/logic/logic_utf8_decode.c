
#include <stdint.h>
static uint64_t rd(const unsigned char *p) {uint64_t v=0;for(unsigned i=0;i<8;i++)v|=(uint64_t)p[i]<<(8*i);return v;}
static void wr(unsigned char *p,uint64_t v) {for(unsigned i=0;i<8;i++)p[i]=(unsigned char)(v>>(8*i));}
static unsigned char at(uint64_t p,unsigned i) {return *(const unsigned char *)(uintptr_t)(p+i);}
uint32_t logic_utf8_decode(unsigned char *s) {
 const uint32_t error=0x8000fffdU;uint64_t p=rd(s);unsigned lead=at(p,0),n=0;
 for(unsigned bit=128;bit && (lead&bit);bit>>=1)++n;
 if(n==0) {wr(s,p+1);return at(p,0);}
 if(n<2||n>4) {wr(s,p+1);return error;}
 uint64_t available=rd(s+8)-p;
 if((available>>63)||available<n) {wr(s,p+1);return error;}
 for(unsigned i=1;i<n;i++) if((at(p,i)&0xc0)!=0x80) {wr(s,p+1);return error;}
 wr(s,p+1);unsigned a=at(p,0)&(n==2?31:n==3?15:7);
 if(n==2) {wr(s,p+2);if(a<2)return error;return (a<<6)|(at(p,1)&63);}
 wr(s,p+2);unsigned b=at(p,1);unsigned prefix=(a<<12)|((b&63)<<6);
 if(n==3) {
  wr(s,p+3);if(prefix<0x800)return error;
  unsigned c=at(p,2)&63;return (prefix&0xf800)==0xd800?error:prefix|c;
 }
 wr(s,p+3);unsigned c=at(p,2);wr(s,p+4);
 if(prefix<0x400)return error;
 unsigned result=(((prefix|(c&63))<<6)|(at(p,3)&63));
 return (prefix>>10)<17?result:error;
}
