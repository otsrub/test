/* Original-byte translation: GImage::SetImportLUT, 0x865e4..0x86630.
 * The original symbol GImage::ms_ImportLUT at 0x474190 is in zerofill
 * __common and spans 256 bytes before the next symbol. Recover that real
 * shared data symbol, rather than a successful external-call placeholder.
 * Other users of this shared state and complete image integration remain open.
 */
typedef unsigned char u8;
class GImage { public: static u8 ms_ImportLUT[256]; };
u8 GImage::ms_ImportLUT[256];
extern "C" void ml_gui_set_import_lut(const u8*input){
 for(unsigned group=0;group<4;group++){
  u8 loaded[64];
  for(unsigned k=0;k<64;k++)loaded[k]=input[group*64+k];
  for(unsigned k=32;k<64;k++)GImage::ms_ImportLUT[group*64+k]=loaded[k];
  for(unsigned k=0;k<32;k++)GImage::ms_ImportLUT[group*64+k]=loaded[k];
 }
}
