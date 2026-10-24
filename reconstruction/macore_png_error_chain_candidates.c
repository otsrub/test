/* Native error-chain source candidates. Real external stdio/abort and callback
 * ABI dependencies remain. Object compilation is not execution verification. */
typedef unsigned char u8;typedef unsigned long long u64;
extern void*__stderrp;
extern int fprintf(void*,const char*,...);
extern int fputc(int,void*);
extern void abort(void) __attribute__((noreturn));
static u64 r64(const u8*p){u64 v=0;for(unsigned k=0;k<8;k++)v|=(u64)p[k]<<(8*k);return v;}
void ml_png_longjmp_candidate(u8*p,int value) __attribute__((noreturn));
void ml_png_longjmp_candidate(u8*p,int value){
 if(p){u64 callback=r64(p+0xc0);if(callback){void*buffer=(void*)r64(p+0xc8);if(buffer)((void(*)(void*,int))callback)(buffer,value);}}
 abort();
}
void ml_png_default_error_candidate(u8*p,const char*message) __attribute__((noreturn));
void ml_png_default_error_candidate(u8*p,const char*message){
 fprintf(__stderrp,"libpng error: %s",message?message:"undefined");
 fputc(10,__stderrp);
 ml_png_longjmp_candidate(p,1);
}
void ml_png_error_candidate(u8*p,const char*message) __attribute__((noreturn));
void ml_png_error_candidate(u8*p,const char*message){
 if(p){u64 callback=r64(p+0xd8);if(callback)((void(*)(u8*,const char*))callback)(p,message);}
 ml_png_default_error_candidate(p,message);
}
