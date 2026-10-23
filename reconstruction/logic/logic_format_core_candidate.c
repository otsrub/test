
#include <stdint.h>
static uint64_t rd(const unsigned char*p,unsigned n){uint64_t x=0;for(unsigned i=0;i<n;i++)x|=(uint64_t)p[i]<<(8*i);return x;}
static void wr(unsigned char*p,uint64_t x,unsigned n){for(unsigned i=0;i<n;i++)p[i]=(unsigned char)(x>>(8*i));}
static unsigned ch(uint64_t p){return *(const unsigned char*)(uintptr_t)p;}

extern void logic_format_error_original_8b4614(const char *) __attribute__((noreturn));
extern void *memmove(void *,const void *,__SIZE_TYPE__);
struct argid_result {uint64_t ptr,index;};
static struct argid_result logic_argid(uint64_t p,uint64_t end,unsigned char *ctx){
 unsigned c=ch(p),value=c-'0',mode;uint64_t q=p,msg=0;
 if(c=='}'||c==':'){
  mode=(unsigned)rd(ctx+16,4);
  if(mode==1){msg=0x10927db;goto error;}
  if(mode==0)wr(ctx+16,2,4);
  uint64_t index=rd(ctx+24,8);wr(ctx+24,index+1,8);value=(unsigned)index;goto done;
 }
 if(c=='0'){q=p+1;value=0;goto manual;}
 if(c<'1'||c>'9'){msg=0x1092762;goto error;}
 q=p+1;uint64_t stop=(end-p>9)?p+9:end;
 while(q<stop){c=ch(q);if(c<'0'||c>'9')goto manual;value=value*10+c-'0';q++;}
 if(q==end)goto manual;
 c=ch(q);if(c<'0'||c>'9')goto manual;
 uint64_t large=(uint64_t)value*10+c-'0';
 if(large>=0x80000000ULL){msg=0x1092820;goto error;}
 value=(unsigned)large;q++;
 if(q!=end){c=ch(q);if(c>='0'&&c<='9'){msg=0x1092820;goto error;}}
 manual:
 mode=(unsigned)rd(ctx+16,4);
 if(mode==2){msg=0x1092796;goto error;}
 if(mode==0)wr(ctx+16,1,4);
 done:return (struct argid_result){q,value};
 error:logic_format_error_original_8b4614((const char*)(uintptr_t)msg);
}

static unsigned logic_decimal(unsigned char *spec,unsigned char *cursor,uint64_t end,
                   uint64_t parsectx,unsigned precision){
 uint64_t p=rd(cursor,8),q=p,msg=0,ret=0;unsigned c=ch(p);
 if(precision){if(c!='.')goto done;q=p+1;wr(cursor,q,8);if(q==end){msg=0x10929c9;goto error;}c=ch(q);}
 if(c=='{'){
  q++;wr(cursor,q,8);if(q==end){msg=0x109297e;goto error;}
  struct argid_result id=logic_argid(q,end,(unsigned char*)(uintptr_t)parsectx);
  q=id.ptr;if(q==end||ch(q)!='}'){msg=0x10929ab;goto error;}
  q++;wr(spec+2,rd(spec+2,2)|(precision?0x8000:0x4000),2);
  wr(spec+(precision?8:4),id.index,4);wr(cursor,q,8);ret=1;goto done;
 }
 if(c<'0'||c>'9'){if(precision){msg=0x10929ff;goto error;}goto done;}
 if(!precision&&c=='0'){msg=0x109294e;goto error;}
 uint64_t value=0;unsigned digits=0;
 do{
  value=value*10+ch(q)-'0';digits++;q++;
  if(value>0x7fffffffULL){msg=0x1092820;goto error;}
  if(q==end)break;
  c=ch(q);if(c<'0'||c>'9')break;
  if(digits==10){msg=0x1092820;goto error;}
 }while(1);
 wr(spec+(precision?8:4),value,4);
 if(precision)wr(spec+2,rd(spec+2,2)&0x7fff,2);
 wr(cursor,q,8);ret=1;
 done:return (unsigned)ret;
 error:logic_format_error_original_8b4614((const char*)(uintptr_t)msg);
}


#include <stdint.h>
static uint64_t utf_rd(const unsigned char *p) {uint64_t v=0;for(unsigned i=0;i<8;i++)v|=(uint64_t)p[i]<<(8*i);return v;}
static void utf_wr(unsigned char *p,uint64_t v) {for(unsigned i=0;i<8;i++)p[i]=(unsigned char)(v>>(8*i));}
static unsigned char utf_at(uint64_t p,unsigned i) {return *(const unsigned char *)(uintptr_t)(p+i);}
uint32_t logic_utf8_decode(unsigned char *s) {
 const uint32_t error=0x8000fffdU;uint64_t p=utf_rd(s);unsigned lead=utf_at(p,0),n=0;
 for(unsigned bit=128;bit && (lead&bit);bit>>=1)++n;
 if(n==0) {utf_wr(s,p+1);return utf_at(p,0);}
 if(n<2||n>4) {utf_wr(s,p+1);return error;}
 uint64_t available=utf_rd(s+8)-p;
 if((available>>63)||available<n) {utf_wr(s,p+1);return error;}
 for(unsigned i=1;i<n;i++) if((utf_at(p,i)&0xc0)!=0x80) {utf_wr(s,p+1);return error;}
 utf_wr(s,p+1);unsigned a=utf_at(p,0)&(n==2?31:n==3?15:7);
 if(n==2) {utf_wr(s,p+2);if(a<2)return error;return (a<<6)|(utf_at(p,1)&63);}
 utf_wr(s,p+2);unsigned b=utf_at(p,1);unsigned prefix=(a<<12)|((b&63)<<6);
 if(n==3) {
  utf_wr(s,p+3);if(prefix<0x800)return error;
  unsigned c=utf_at(p,2)&63;return (prefix&0xf800)==0xd800?error:prefix|c;
 }
 utf_wr(s,p+3);unsigned c=utf_at(p,2);utf_wr(s,p+4);
 if(prefix<0x400)return error;
 unsigned result=(((prefix|(c&63))<<6)|(utf_at(p,3)&63));
 return (prefix>>10)<17?result:error;
}

void logic_presentation(unsigned char *spec,unsigned char *cursor) {
 uint64_t p=rd(cursor,8);unsigned t;
 switch(*(const unsigned char *)(uintptr_t)p) {
 case '?':t=19;break;case 'A':t=12;break;case 'B':t=3;break;
 case 'E':t=14;break;case 'F':t=16;break;case 'G':t=18;break;
 case 'P':t=9;break;case 'X':t=7;break;case 'a':t=11;break;
 case 'b':t=2;break;case 'c':t=10;break;case 'd':t=5;break;
 case 'e':t=13;break;case 'f':t=15;break;case 'g':t=17;break;
 case 'o':t=4;break;case 'p':t=8;break;case 's':t=1;break;
 case 'x':t=6;break;default:return;
 }
 spec[1]=(unsigned char)t;wr(cursor,p+1,8);
}


static unsigned alignment(unsigned c){return c=='<'?1:c=='>'?3:c=='^'?2:0;}
unsigned logic_fill(unsigned char *spec,unsigned char *cursor,uint64_t end){
 uint64_t first=rd(cursor,8),state[2]={first,end};
 uint32_t decoded=logic_utf8_decode((unsigned char*)state);
 if(decoded>>31)logic_format_error_original_8b4614((const char*)0x10928e9);
 uint64_t q=state[0];unsigned al=0;
 if(q<end)al=alignment(ch(q));
 if(al){
  spec[0]=(unsigned char)((spec[0]&0xf8)|al);
  uint64_t p=rd(cursor,8),length=q-p;
  if(length==1){unsigned c=ch(p);if(c=='{')logic_format_error_original_8b4614((const char*)0x1092924);spec[12]=(unsigned char)c;}
  else if(q!=p)memmove(spec+12,(const void*)(uintptr_t)p,length);
  wr(cursor,rd(cursor,8)+length+1,8);return 1;
 }
 al=alignment(ch(first));if(!al)return 0;
 spec[0]=(unsigned char)((spec[0]&0xf8)|al);wr(cursor,rd(cursor,8)+1,8);return 1;
}
unsigned logic_width(unsigned char*s,unsigned char*c,uint64_t end,uint64_t ctx){return logic_decimal(s,c,end,ctx,0);}
unsigned logic_precision(unsigned char*s,unsigned char*c,uint64_t end,uint64_t ctx){return logic_decimal(s,c,end,ctx,1);}
uint64_t logic_format_specs(unsigned char *spec,unsigned char *ctx,unsigned mask){
 uint64_t p=rd(ctx,8),end=rd(ctx+8,8);mask&=0xffff;
 if(p==end||ch(p)=='}'||((mask&64)&&ch(p)==':'))return p;
 unsigned changed=logic_fill(spec,(unsigned char*)&p,end);
 if(changed&&p==end)return p;
 if(mask&1){unsigned c=ch(p),sign=0;
  if(c=='-')sign=8;else if(c=='+')sign=16;else if(c==' ')sign=24;
  if(sign){spec[0]=(unsigned char)((spec[0]&0xe7)|sign);p++;if(p==end)return p;}
 }
 if((mask&2)&&ch(p)=='#'){spec[0]|=32;p++;if(p==end)return p;}
 if((mask&4)&&ch(p)=='0'){if(!(spec[0]&7))spec[0]|=4;p++;if(p==end)return p;}
 changed=logic_width(spec,(unsigned char*)&p,end,(uint64_t)(uintptr_t)ctx);if(changed&&p==end)return p;
 if(mask&8){changed=logic_precision(spec,(unsigned char*)&p,end,(uint64_t)(uintptr_t)ctx);if(changed&&p==end)return p;}
 if((mask&16)&&ch(p)=='L'){spec[0]|=64;p++;if(p==end)return p;}
 if((mask&128)&&ch(p)=='n'){spec[0]|=128;p++;if(p==end)return p;}
 if(mask&32)logic_presentation(spec,(unsigned char*)&p);
 if((mask&256)&&p!=end&&ch(p)!='}')logic_format_error_original_8b4614((const char*)0x10928a9);
 return p;
}
