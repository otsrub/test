/* Source composition for tag-3 visitor and signed-int formatter.
 * Real original output/error dependencies remain unresolved, never fake stubs. */
#include "logic_format_core_candidate.c"
#include "logic_format_validate_candidate.c"
typedef struct {uint64_t first,second;} SpecPair;
static uint32_t logic_numeric_value(const unsigned char *v,unsigned tag){
 uint64_t x=0,msg=0;
 switch(tag){
 case 3:x=rd(v,4);if(x>>31)msg=0x1092b65;break;
 case 4:x=rd(v,8);if(x>>63)msg=0x1092b65;else if(x>>31)msg=0x1092b95;break;
 case 6:x=rd(v,4);if(x>>31)msg=0x1092b95;break;
 case 7:x=rd(v,8);if(x>>31)msg=0x1092b95;break;
 case 0:msg=0x1092857;break;
 default:msg=0x1092b1f;break;
 }
 if(msg)logic_format_error_original_8b4614((const char*)(uintptr_t)msg);
 return (uint32_t)x;
}
static uint32_t logic_dynamic_value(const unsigned char *fmt,int32_t index){
 uint64_t count=rd(fmt+8,8),slot=(uint64_t)(int64_t)index;
 if(count<=slot)return logic_numeric_value((const unsigned char*)0,0);
 uint64_t ptr=rd(fmt+16,8);unsigned tag;
 if(count<=12){tag=(unsigned)(rd(fmt+24,8)>>((5*(unsigned)index)&63))&31;ptr+=slot*16;}
 else{ptr+=slot*32;tag=ch(ptr+16);}
 return logic_numeric_value((const unsigned char*)(uintptr_t)ptr,tag);
}
SpecPair logic_resolved_specs_expanded(const unsigned char *spec,const unsigned char *fmt){
 unsigned flag=(unsigned)rd(spec+2,2);uint32_t width=(uint32_t)rd(spec+4,4),precision=(uint32_t)rd(spec+8,4);
 if(flag&0x4000)width=logic_dynamic_value(fmt,(int32_t)width);
 if(flag&0x8000)precision=logic_dynamic_value(fmt,(int32_t)precision);
 return (SpecPair){(spec[0]&127)|((uint64_t)spec[1]<<8)|((uint64_t)width<<32),precision|(rd(spec+12,4)<<32)};
}
extern uint64_t logic_integer_output_original_8c05bc(uint32_t,unsigned char*,uint64_t,uint64_t,unsigned);
extern void logic_character_output_original_8b86dc(const unsigned char*,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t);
void logic_signed_integer_format(unsigned char *ctx,int32_t value){
 unsigned char spec[16]={0};wr(spec+8,0xffffffff,4);spec[12]=32;
 if(ch(rd(ctx+16,8))==1){
  unsigned char *parse=(unsigned char*)(uintptr_t)rd(ctx,8);uint64_t p=logic_format_specs(spec,parse,0x137);unsigned type=spec[1];
  if(type!=0 && !(type>=2&&type<=7)){
   if(type!=10)logic_presentation_error_original_8b5ab0((const char*)0x1092c3b);
   logic_format_validate(spec,0x130,(const char*)0x1092c3b,0xffffffff);
   if(!(spec[0]&7))spec[0]|=1;
  }
  wr(parse,p,8);
 }
 unsigned char *fmt=(unsigned char*)(uintptr_t)rd(ctx+8,8);SpecPair pair=logic_resolved_specs_expanded(spec,fmt);uint64_t output;
 if((pair.first&0xff00)==0xa00){
  if(value!=(int32_t)(int8_t)value)logic_format_error_original_8b4614((const char*)0x1092c46);
  unsigned char c=(unsigned char)value;output=rd(fmt,8);
  logic_character_output_original_8b86dc(&c,1,output,pair.first,pair.second,1);
 }else{
  uint32_t magnitude=value<0?0U-(uint32_t)value:(uint32_t)value;
  output=logic_integer_output_original_8c05bc(magnitude,fmt,pair.first,pair.second,(unsigned)(value<0));
 }
 wr(fmt,output,8);
}
void logic_tag3_visitor(unsigned char *ctx,const unsigned char *value){logic_signed_integer_format(ctx,(int32_t)rd(value,4));}
