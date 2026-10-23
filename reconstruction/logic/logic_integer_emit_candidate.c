/* Real source composition. Locale dispatch retains a real unresolved native
 * dependency at the original function entry; its body is not claimed recovered. */
#include "logic_integer_digits.c"
#include "logic_buffer_transform_candidate.c"
#include "logic_integer_path_candidate.c"
extern uint64_t logic_locale_emitter_original_8c070c(uint32_t,unsigned char*,uint64_t,uint64_t,unsigned,unsigned char*,unsigned char*,const char*,uint32_t);
uint64_t logic_integer_output_original_8c05bc(uint32_t value,unsigned char *fmt,uint64_t first,uint64_t second,unsigned negative){
 unsigned type=(unsigned)(first>>8)&255,base,capacity;const char *prefix;
 if(type==0||type==5){base=10;capacity=11;prefix=0;}
 else if(type==4){base=8;capacity=13;prefix=value?"0":0;first=(first&~0xff00ULL)|0x400;}
 else if(type<=3){base=2;capacity=35;if(type==2){prefix="0b";first=(first&~0xff00ULL)|0x200;}else{prefix="0B";first=(first&~0xff00ULL)|0x300;}}
 else{base=16;capacity=11;if(type==6){prefix="0x";first=(first&~0xff00ULL)|0x600;}else{prefix="0X";first=(first&~0xff00ULL)|0x700;}}
 unsigned char buffer[40],*digits=buffer;
 if(first&64)return logic_locale_emitter_original_8c070c(value,fmt,first,second,negative,buffer,buffer+capacity,prefix,base);
 unsigned sign=((unsigned)first>>3)&3;
 if(negative&1)*digits++='-';else if(sign==2)*digits++='+';else if(sign==3)*digits++=' ';
 if((first&32)&&prefix){while(*prefix)*digits++=(unsigned char)*prefix++;}
 LogicCharsResult result=logic_to_chars32(digits,buffer+capacity,value,base);unsigned char *last=result.ptr;
 unsigned char *out=(unsigned char*)(uintptr_t)b_read(fmt);uint32_t width=(uint32_t)(first>>32);unsigned flags=(unsigned)first&255;
 if((flags&7)==4){
  uint64_t prefix_length=(uint64_t)(digits-buffer),selected;
  if(select_limit(out,prefix_length,&selected))buffer_copy(out,buffer,selected,1);
  width-=(int32_t)width<(int32_t)prefix_length?width:(uint32_t)prefix_length;
  flags=(flags&0xf8)|3;second=(second&~(0xffULL<<32))|(0x30ULL<<32);out=(unsigned char*)(uintptr_t)b_read(fmt);
 }else digits=buffer;
 first=(first&0x00000000ffffff00ULL)|flags|((uint64_t)width<<32);
 if((first&0xff00)==0x700)logic_buffer_transform(digits,last,out,first,second,logic_hex_upper);
 else logic_buffer_string(digits,(uint64_t)(last-digits),out,first,second,(uint64_t)(last-digits));
 return (uint64_t)(uintptr_t)out;
}
void logic_character_output_original_8b86dc(const unsigned char*text,uint64_t size,uint64_t out,uint64_t first,uint64_t second,uint64_t visual){logic_buffer_string(text,size,(unsigned char*)(uintptr_t)out,first,second,visual);}
uint64_t logic_complete_tag3_visitor(unsigned char *ctx,const unsigned char *value){logic_tag3_visitor(ctx,value);return rd((const unsigned char*)(uintptr_t)rd(ctx+8,8),8);}
uint64_t logic_complete_signed_formatter(unsigned char *ctx,int32_t value){logic_signed_integer_format(ctx,value);return rd((const unsigned char*)(uintptr_t)rd(ctx+8,8),8);}
