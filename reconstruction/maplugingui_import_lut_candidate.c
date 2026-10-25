/* Unverified instruction-derived candidate: GImage::SetImportLUT, original
 * MAPlugInGUI 0x865e4..0x86630. Original shared data destination is 0x474190.
 * Its shared-data owner/initialization and runtime composition remain open.
 * Retain a real unresolved data declaration; do not synthesize a zero LUT.
 */
typedef unsigned char u8;
extern u8 ml_gui_shared_import_lut[256];
void ml_gui_set_import_lut_candidate(const u8*input){
 for(unsigned group=0;group<4;group++){
  u8 loaded[64];
  for(unsigned k=0;k<64;k++)loaded[k]=input[group*64+k];
  /* Original loads all four q-registers before writing second pair first. */
  for(unsigned k=32;k<64;k++)ml_gui_shared_import_lut[group*64+k]=loaded[k];
  for(unsigned k=0;k<32;k++)ml_gui_shared_import_lut[group*64+k]=loaded[k];
 }
}
