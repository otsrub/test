
#include <stdint.h>
static uint64_t rd(const unsigned char*p,unsigned n){uint64_t x=0;for(unsigned i=0;i<n;i++)x|=(uint64_t)p[i]<<(8*i);return x;}
static void wr(unsigned char*p,uint64_t x,unsigned n){for(unsigned i=0;i<n;i++)p[i]=(unsigned char)(x>>(8*i));}
static unsigned ch(uint64_t p){return *(const unsigned char*)(uintptr_t)p;}
void logic_argid(uint64_t p,uint64_t end,unsigned char *ctx,uint64_t out[3]){
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
 done:out[0]=0;out[1]=q;out[2]=value;return;
 error:out[0]=1;out[1]=msg;out[2]=0;
}
