#include <stdint.h>
extern void logic_format_error_original_8b4614(const char *) __attribute__((noreturn));
extern void logic_flag_error_original_8bfc08(const char *,const char *) __attribute__((noreturn));
extern void logic_presentation_error_original_8b5ab0(const char *) __attribute__((noreturn));
static uint32_t read32(const unsigned char *p){return (uint32_t)p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24);}
void logic_format_validate(const unsigned char *spec,unsigned mask,const char *type_name,uint32_t allowed){
 if(!(mask&1)&&(spec[0]&0x18))logic_flag_error_original_8bfc08(type_name,(const char*)0x1092a42);
 mask&=0xffff;
 if(!(mask&2)&&(spec[0]&0x20))logic_flag_error_original_8bfc08(type_name,(const char*)0x1092a47);
 if(!(mask&4)&&((spec[0]&7)==4))logic_flag_error_original_8bfc08(type_name,(const char*)0x1092a56);
 if(!(mask&8)&&read32(spec+8)!=0xffffffffU)logic_flag_error_original_8bfc08(type_name,(const char*)0x1092a63);
 if(!(mask&16)&&(spec[0]&0x40))logic_flag_error_original_8bfc08(type_name,(const char*)0x1092a6d);
 unsigned type=spec[1];
 if(type>=32)logic_format_error_original_8b4614((const char*)0x1092ab9);
 if(!(allowed&(1U<<type)))logic_presentation_error_original_8b5ab0(type_name);
}
