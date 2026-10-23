/* Exact original function counterparts. Domain: uint32 values, bases 2..36,
 * ordinary mapped output memory. No imports, original code bytes or stubs. */
#include <stdint.h>
typedef struct {unsigned char *ptr;uint64_t error;} LogicCharsResult;
unsigned logic_digit_count32(uint32_t value,uint32_t base){unsigned n=1;while(value>=base){value/=base;n++;}return n;}
unsigned char *logic_decimal_write32(unsigned char *dst,uint64_t raw){
 uint32_t value=(uint32_t)raw;unsigned n=logic_digit_count32(value,10);unsigned char *end=dst+n,*p=end;
 do{*--p=(unsigned char)('0'+value%10);value/=10;}while(value);return end;
}
static LogicCharsResult power_chars(unsigned char *dst,unsigned char *end,uint32_t value,unsigned shift){
 unsigned bits=1;for(uint32_t v=value;v>>=1;)bits++;unsigned n=(bits+shift-1)/shift;
 if((int64_t)((uint64_t)(uintptr_t)end-(uint64_t)(uintptr_t)dst)<(int64_t)n)return (LogicCharsResult){end,0x54};
 unsigned char *result=dst+n,*p=result;static const unsigned char digits[]="0123456789abcdef";uint32_t mask=(1U<<shift)-1;
 do{*--p=digits[value&mask];value>>=shift;}while(value);return (LogicCharsResult){result,0};
}
LogicCharsResult logic_binary32(unsigned char*d,unsigned char*e,uint32_t v){return power_chars(d,e,v,1);}
LogicCharsResult logic_octal32(unsigned char*d,unsigned char*e,uint32_t v){return power_chars(d,e,v,3);}
LogicCharsResult logic_hex32(unsigned char*d,unsigned char*e,uint32_t v){return power_chars(d,e,v,4);}
LogicCharsResult logic_to_chars32(unsigned char *dst,unsigned char *end,uint32_t value,uint32_t base){
 if(base==2)return logic_binary32(dst,end,value);
 if(base==8)return logic_octal32(dst,end,value);
 if(base==16)return logic_hex32(dst,end,value);
 unsigned n=logic_digit_count32(value,base);if((int64_t)((uint64_t)(uintptr_t)end-(uint64_t)(uintptr_t)dst)<(int64_t)n)return (LogicCharsResult){end,0x54};
 if(base==10)return (LogicCharsResult){logic_decimal_write32(dst,value),0};
 static const unsigned char digits[]="0123456789abcdefghijklmnopqrstuvwxyz";unsigned char *result=dst+n,*p=result;
 do{*--p=digits[value%base];value/=base;}while(value);return (LogicCharsResult){result,0};
}
