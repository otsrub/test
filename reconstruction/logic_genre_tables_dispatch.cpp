// Original Logic 0xe2d0c0..0xe2d1e4 (292 bytes), warning queue artifact11881406780.
// Returned aggregate layout is inferred from the 24-byte hidden-x8 result footprint.
// Real native dependencies below are unresolved, not replaced with callback stubs.
using Q=unsigned long long;
struct Result {Q words[3]; ~Result(){};};
#define DEP(local,symbol) extern "C" Result local(void*) asm(symbol)
DEP(bVII,"_ZN9Harmonies26CScaleAlternativesForChord17_GenreTables_bVIIEv");
DEP(bVI_before_bVII,"_ZN9Harmonies26CScaleAlternativesForChord28_GenreTables_bVI_before_bVIIEv");
DEP(passing_dim,"_ZN9Harmonies26CScaleAlternativesForChord23_GenreTables_PassingDimEv");
DEP(Vm,"_ZN9Harmonies26CScaleAlternativesForChord15_GenreTables_VmEv");
DEP(secondary_dominant,"_ZN9Harmonies26CScaleAlternativesForChord30_GenreTables_SecondaryDominantEv");
DEP(secondary_IIm,"_ZN9Harmonies26CScaleAlternativesForChord25_GenreTables_SecondaryIImEv");
DEP(bIII,"_ZN9Harmonies26CScaleAlternativesForChord17_GenreTables_bIIIEv");
DEP(bVII_after_bVI,"_ZN9Harmonies26CScaleAlternativesForChord27_GenreTables_bVII_after_bVIEv");
DEP(bII,"_ZN9Harmonies26CScaleAlternativesForChord16_GenreTables_bIIEv");
DEP(bVI,"_ZN9Harmonies26CScaleAlternativesForChord16_GenreTables_bVIEv");
DEP(IVm,"_ZN9Harmonies26CScaleAlternativesForChord16_GenreTables_IVmEv");
extern "C" Result key_V_VII(void*,const void*) asm("_ZN9Harmonies26CScaleAlternativesForChord58_GenreTables_SignKeyMajorDegreeV_and_SignKeyMinorDegreeVIIERK7CKeyEnh");
extern "C" Result key_VIm_Im(void*,const void*) asm("_ZN9Harmonies26CScaleAlternativesForChord59_GenreTables_SignKeyMajorDegreeVIm_and_SignKeyMinorDegreeImERK7CKeyEnh");
extern "C" Result key_I_III(void*,const void*) asm("_ZN9Harmonies26CScaleAlternativesForChord58_GenreTables_SignKeyMajorDegreeI_and_SignKeyMinorDegreeIIIERK7CKeyEnh");
extern "C" bool has_interval(const void*,int) asm("_ZNK10CSemitones8HasIntvlEi");
extern "C" Result ml_logic_genre_tables_dispatch(void* object) {
 auto p=(unsigned char*)object;unsigned genre;__builtin_memcpy(&genre,p+0x198,4);
 switch(genre){
 case 1:return secondary_dominant(object);
 case 2:return secondary_IIm(object);
 case 3:return bVI_before_bVII(object);
 case 4:return bVII_after_bVI(object);
 case 5:return bII(object);
 case 6:return bIII(object);
 case 7:return IVm(object);
 case 8:return Vm(object);
 case 9:return bVI(object);
 case 10:return bVII(object);
 case 11:return passing_dim(object);
 case 12:
  if(p[0x60]==2)return key_VIm_Im(object,p+0x38);
  if(p[0x60]==1){if(has_interval(p+0x50,10))return key_V_VII(object,p+0x38);return key_I_III(object,p+0x38);}
  break;
 default:break;
 }
 return Result{};
}
