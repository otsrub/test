/* Instruction-derived SIMD rectangle candidates from original MAPlugInGUI.
 * Nontrivial return type forces original AAPCS64 hidden-result x8 ABI.
 * The empty destructor provides ABI classification, no runtime callee stub.
 * No accepted-source claim until original-byte tests pass. */
#pragma STDC FENV_ACCESS ON
typedef unsigned int uv4 __attribute__((vector_size(16)));
typedef float fv4 __attribute__((vector_size(16)));
struct MLRectResult { uv4 bits; explicit MLRectResult(uv4 x):bits(x){} ~MLRectResult(){} };
static uv4 calculate(const void*a,const void*b,bool intersection){
 uv4 au,bu;__builtin_memcpy(&au,a,16);__builtin_memcpy(&bu,b,16);
 fv4 af,bf;__builtin_memcpy(&af,&au,16);__builtin_memcpy(&bf,&bu,16);
 fv4 v2=__builtin_shufflevector(af,bf,0,1,6,7),v3=__builtin_shufflevector(bf,af,0,1,6,7);
 uv4 mask=(uv4)(intersection?(v2>v3):(v3>v2));
 uv4 chosen=(au&mask)|(bu&~mask);fv4 f;__builtin_memcpy(&f,&chosen,16);
 /* Original compares both lower lanes before reducing the comparison masks. */
 fv4 high=__builtin_shufflevector(f,f,2,3,2,3);uv4 invalid=(uv4)(f>high);
 unsigned empty=invalid[0]|invalid[1];
 const uv4 sentinel={0x4e6e6b28u,0x4e6e6b28u,0xce6e6b28u,0xce6e6b28u};
 return empty?sentinel:chosen;
}
extern "C" MLRectResult ml_rect_union(const void*a,const void*b){return MLRectResult(calculate(a,b,false));}
extern "C" MLRectResult ml_rect_intersection(const void*a,const void*b){return MLRectResult(calculate(a,b,true));}
