// Recovered MADSP 0x4f59b4..0x4f5a18. Symbol footprint is 136 bytes; high-level field type remains inferred.
using Q=unsigned long long; using V=Q __attribute__((vector_size(16)));
class WrinkleAnalogShell { public: static Q m_pFader2ParaMap[17]; };
Q WrinkleAnalogShell::m_pFader2ParaMap[17];
extern "C" { unsigned char ml_madsp_global_guard[1024]; }
static inline void put(unsigned off,V v){__builtin_memcpy((unsigned char*)WrinkleAnalogShell::m_pFader2ParaMap+off,&v,16);}
extern "C" Q ml_madsp_fader_map_init(Q x0) {
 const V ff={~Q(0),~Q(0)};
 put(64,ff);put(80,ff);put(96,ff);put(112,ff);
 put(0,ff);put(16,V{0,1});put(32,V{2,3});put(48,V{4,5});
 put(72,V{6,7});put(88,V{8,9});put(104,V{10,11});
 WrinkleAnalogShell::m_pFader2ParaMap[16]=12;
 return x0;
}
