/* Post-helper constructor phase 0x896250..0x896368 only.
 * Preserve every untouched byte in seven 24-byte inline-string slots. */
#include <stdint.h>
static void store64(unsigned char*p,uint64_t x){for(unsigned i=0;i<8;i++)p[i]=(unsigned char)(x>>(8*i));}
static void inline_string(unsigned char*p,const char *s,unsigned length){for(unsigned i=0;i<length;i++)p[i]=(unsigned char)s[i];p[length]=0;p[23]=(unsigned char)length;}
void madsp_pub_offset_identifiers(unsigned char *object,unsigned char *frame,uint64_t transfer[8]){
 inline_string(frame+0x3c0,"growlNormalOffsets",18);
 inline_string(frame+0x3d8,"growlBlendOffsets",17);
 inline_string(frame+0x3f0,"growlRGBOffsets",15);
 inline_string(frame+0x408,"growlFFFOffsets",15);
 inline_string(frame+0x420,"growlHamOffsets",15);
 inline_string(frame+0x438,"growlPullOffsets",16);
 inline_string(frame+0x450,"growlVibratoOffsets",19);
 for(unsigned i=0;i<24;i++)object[0x57c0+i]=0;
 store64(frame+0x170,(uint64_t)(uintptr_t)object);
 transfer[0]=0x52418;transfer[1]=(uint64_t)(uintptr_t)(object+0x57c0);transfer[2]=(uint64_t)(uintptr_t)(frame+0x3c0);transfer[3]=(uint64_t)(uintptr_t)(frame+0x468);transfer[4]=7;
 transfer[5]=(uint64_t)(uintptr_t)(frame+0x390);transfer[6]=0x57c0;transfer[7]=(uint64_t)(uintptr_t)(frame+0x3c0);
}

/* After actual allocation return; no allocation or assignment is simulated. */
void madsp_pub_attack_identifiers(unsigned char*object,unsigned char*frame,unsigned char*heap,uint64_t transfer[8]){
 (void)object;
 store64(frame+0x3c0,(uint64_t)(uintptr_t)heap);
 store64(frame+0x3c8,26);store64(frame+0x3d0,UINT64_C(0x8000000000000020));
 const char*s="instrumentModelAttackTimes";for(unsigned i=0;i<26;i++)heap[i]=(unsigned char)s[i];heap[26]=0;
 inline_string(frame+0x3d8,"hamModelAttackTimes",19);
 inline_string(frame+0x3f0,"pullModelAttackTimes",20);
 transfer[0]=0xc13b48;transfer[1]=40;transfer[2]=(uint64_t)(uintptr_t)heap;
 for(unsigned i=3;i<8;i++)transfer[i]=0;
}
void madsp_pub_attack_point(unsigned char*object,unsigned char*frame,unsigned char*heap,uint64_t transfer[8]){
 store64(frame+0x408,(uint64_t)(uintptr_t)heap);
 store64(frame+0x410,33);store64(frame+0x418,UINT64_C(0x8000000000000028));
 const char*s="instrument10DBDownAttackTimePoint";for(unsigned i=0;i<33;i++)heap[i]=(unsigned char)s[i];heap[33]=0;
 for(unsigned i=0;i<24;i++)object[0x57d8+i]=0;
 transfer[0]=0x52418;transfer[1]=(uint64_t)(uintptr_t)(object+0x57d8);
 transfer[2]=(uint64_t)(uintptr_t)(frame+0x3c0);transfer[3]=(uint64_t)(uintptr_t)(frame+0x420);transfer[4]=4;
 transfer[5]=(uint64_t)(uintptr_t)(object+0x57d8);transfer[6]=(uint64_t)(uintptr_t)(frame+0x3c0);transfer[7]=0;
}
