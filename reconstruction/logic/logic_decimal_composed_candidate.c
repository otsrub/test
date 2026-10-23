
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

void logic_decimal(unsigned char *spec,unsigned char *cursor,uint64_t end,
                   uint64_t parsectx,unsigned precision,uint64_t out[5]){
 uint64_t p=rd(cursor,8),q=p,msg=0,ret=0;unsigned c=ch(p);
 if(precision){if(c!='.')goto done;q=p+1;wr(cursor,q,8);if(q==end){msg=0x10929c9;goto error;}c=ch(q);}
 if(c=='{'){
  q++;wr(cursor,q,8);if(q==end){msg=0x109297e;goto error;}
  uint64_t id[3];logic_argid(q,end,(unsigned char*)(uintptr_t)parsectx,id);
  if(id[0]){msg=id[1];goto error;}
  q=id[1];if(q==end||ch(q)!='}'){msg=0x10929ab;goto error;}
  q++;wr(spec+2,rd(spec+2,2)|(precision?0x8000:0x4000),2);
  wr(spec+(precision?8:4),id[2],4);wr(cursor,q,8);ret=1;goto done;
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
 done:out[0]=0;out[1]=0;out[2]=ret;out[3]=0;out[4]=0;return;
 error:out[0]=1;out[1]=0x8b4614;out[2]=msg;out[3]=0;out[4]=0;
}
