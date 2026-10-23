#include "logic_buffer_output_candidate.c"
int32_t logic_hex_upper(int32_t value){uint32_t v=(uint32_t)value;if(v-(uint32_t)'a'<6)v-=32;return (int32_t)(int8_t)v;}
static void buffer_transform_copy(unsigned char*out,const unsigned char *src,uint64_t remaining,int32_t(*transform)(int32_t)){
 for(;;){
  uint64_t pos=b_read(out+16),available=b_read(out+8)-pos;
  if(available<remaining+1){
   void(*grow)(unsigned char*,uint64_t)=(void(*)(unsigned char*,uint64_t))(uintptr_t)b_read(out+24);
   grow(out,remaining+2);pos=b_read(out+16);available=b_read(out+8)-pos;
  }
  uint64_t take=available<remaining?available:remaining;
  if(take){unsigned char *dst=(unsigned char*)(uintptr_t)(b_read(out)+pos);for(uint64_t i=0;i<take;i++){int32_t c=(int32_t)(int8_t)*src++;*dst++=(unsigned char)transform(c);}}
  b_write(out+16,b_read(out+16)+take);if(remaining<=available)return;remaining-=take;
 }
}
uint64_t logic_buffer_transform(const unsigned char *text,const unsigned char *last,unsigned char*out,uint64_t first,uint64_t second,int32_t(*transform)(int32_t)){
 uint64_t size=(uint64_t)(uintptr_t)last-(uint64_t)(uintptr_t)text;
 uint64_t delta=(uint64_t)((int64_t)first>>32)-size;
 if((int64_t)delta<=0){uint64_t selected;if(select_limit(out,size,&selected))buffer_transform_copy(out,text,selected,transform);}
 else{
  unsigned alignment=(unsigned)first&7;uint64_t leading,trailing,fill=second>>32;
  if(alignment==1){leading=0;trailing=delta;}
  else if(alignment==0||alignment==3){leading=delta;trailing=0;}
  else{leading=delta>>1;trailing=delta-leading;}
  logic_buffer_padding(out,leading,fill);uint64_t selected;if(select_limit(out,size,&selected))buffer_transform_copy(out,text,selected,transform);logic_buffer_padding(out,trailing,fill);
 }
 return (uint64_t)(uintptr_t)out;
}
