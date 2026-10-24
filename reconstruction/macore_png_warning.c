/* Actual warning helper0x47204..0x47390 to its real next callee.
 * Optional full source candidate retains actual callbacks and stdio imports.
 */
#include "macore_png_claim.c"
static const char warning_format[]="libpng warning: %s";
static const unsigned char *warning_message(unsigned char*c,const unsigned char*m){
 if(c && m[0]=='#'){unsigned i=1;while(i<15 && m[i]!=' ')i++;return m+i;}return m;
}
void mobilelogic_png_warning_boundary(unsigned char*c,const unsigned char*m,u64*out,u64 file){
 m=warning_message(c,m);u64 callback=c?r64(c+0xe0):0;
 out[0]=callback?callback:0x104be4;out[1]=callback?(u64)c:file;
 out[2]=callback?0:(u64)warning_format;out[3]=(u64)m;
}
void mobilelogic_png_claim_warning_composed(unsigned char*c,u32 owner,u64*out,u64 file){
 u64 first[16];mobilelogic_png_claim_prefix(c,owner,0,first);
 const unsigned char*m=(const unsigned char*)first+80;
 mobilelogic_png_warning_boundary(c,m,out,file);
 unsigned char*copy=(unsigned char*)out+64;for(unsigned i=0;i<25;i++)copy[i]=m[i];
 out[3]=(u64)copy+(out[3]-(u64)m);
}
#ifdef WARNING_CANDIDATE
extern void *__stderrp;
extern int fprintf(void*,const char*,...);
extern int fputc(int,void*);
void mobilelogic_png_warning_candidate(unsigned char*c,const unsigned char*m){
 m=warning_message(c,m);u64 callback=c?r64(c+0xe0):0;
 if(callback)((void(*)(void*,const unsigned char*))callback)(c,m);
 else{fprintf(__stderrp,warning_format,m);fputc(10,__stderrp);}
}
#endif
