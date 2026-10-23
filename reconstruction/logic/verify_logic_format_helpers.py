"""Presentation parser whole-function tests and numeric conversion call-boundary tests."""
import pathlib,os,json,struct,random,subprocess,hashlib
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
from unicorn.arm64_const import *
ROOT=pathlib.Path.cwd()
parent=(ROOT/'prior/verify_logic_tail_adapters.py').read_text()
exec(parent[:parent.index('archive = ARCHIVE.read_bytes()')])
ROOT=pathlib.Path.cwd()
LANE=os.environ['REA_LANE'];assert LANE in ('presentation','numeric')
OUT=ROOT/('format-'+LANE);OUT.mkdir(exist_ok=True)
original=(ROOT/'dossiers/logic-input/target.bin').read_bytes();assert sha(original)==EXPECTED_LOGIC
SOURCE=r'''
#include <stdint.h>
static uint64_t rd(const unsigned char *p,unsigned n) {
 uint64_t x=0;for(unsigned i=0;i<n;i++)x|=(uint64_t)p[i]<<(i*8);return x;
}
static void wr(unsigned char *p,uint64_t x) {
 for(unsigned i=0;i<8;i++)p[i]=(unsigned char)(x>>(i*8));
}
/* Complete presentation-type parser corresponding to original 0x8be770.
 * Byte accesses intentionally preserve the original order under overlap. */
void logic_presentation(unsigned char *spec,unsigned char *cursor) {
 uint64_t p=rd(cursor,8);unsigned t;
 switch(*(const unsigned char *)(uintptr_t)p) {
 case '?':t=19;break;case 'A':t=12;break;case 'B':t=3;break;
 case 'E':t=14;break;case 'F':t=16;break;case 'G':t=18;break;
 case 'P':t=9;break;case 'X':t=7;break;case 'a':t=11;break;
 case 'b':t=2;break;case 'c':t=10;break;case 'd':t=5;break;
 case 'e':t=13;break;case 'f':t=15;break;case 'g':t=17;break;
 case 'o':t=4;break;case 'p':t=8;break;case 's':t=1;break;
 case 'x':t=6;break;default:return;
 }
 spec[1]=(unsigned char)t;wr(cursor,p+1);
}
/* Numeric conversion result or real original error-message transfer.
 * This describes the cut before the unresolved error function; it is not
 * a replacement for the original throwing helper. Tags outside 0..15 excluded. */
void logic_numeric_cut(const unsigned char *v,uint64_t out[2]) {
 unsigned tag=v[16];uint64_t x=0,msg=0;
 switch(tag) {
 case 3:x=rd(v,4);if(x>>31)msg=0x1092b65;break;
 case 4:x=rd(v,8);if(x>>63)msg=0x1092b65;else if(x>>31)msg=0x1092b95;break;
 case 6:x=rd(v,4);if(x>>31)msg=0x1092b95;break;
 case 7:x=rd(v,8);if(x>>31)msg=0x1092b95;break;
 case 0:msg=0x1092857;break;
 default:msg=0x1092b1f;break;
 }
 out[0]=msg?msg:x;out[1]=msg?0x8b4614:0;
}
'''
(OUT/'logic_format_helpers.c').write_text(SOURCE)
engines=[];diags=[]
for opt in (0,2,3):
 obj=OUT/f'O{opt}.o';lib=OUT/f'O{opt}.dylib'
 for argv in (["clang-18","-target","arm64-apple-ios17.0",f'-O{opt}',"-ffreestanding","-fno-builtin","-Wall","-Wextra","-Werror","-c",str(OUT/'logic_format_helpers.c'),'-o',str(obj)],['ld64.lld-18','-arch','arm64','-platform_version','ios','17.0','17.0','-dylib','-undefined','error',str(obj),'-o',str(lib)]):
  r=subprocess.run(argv,text=True,capture_output=True);diags.append({'argv':argv,'returncode':r.returncode,'stderr':r.stderr});(OUT/'compile.json').write_text(json.dumps(diags,indent=2));assert r.returncode==0,r.stderr
 raw=lib.read_bytes();u,syms=engine(raw);u.mem_map(0x3300000,0x1000)
 symbol='_logic_presentation' if LANE=='presentation' else '_logic_numeric_cut'
 entry=next(v for n,v,undef in syms if n==symbol and not undef);engines.append((u,entry,sha(raw)))
ref,_=engine(original);covered=set();error_sites={0x8be2dc,0x8be2e8,0x8be2f4,0x8be300};state={}
start,end=(0x8be770,0x8be83c) if LANE=='presentation' else (0x8be270,0x8be304)
def hook(u,pc,n,_):
 if pc in error_sites:
  state['error']=True;state['site']=pc;u.emu_stop();return
 covered.add(pc);assert start<=pc<end,hex(pc)
ref.hook_add(UC_HOOK_CODE,hook)
rng=random.Random(start);cases=16384 if LANE=='presentation' else 8192;passes=[0,0,0];failures=[];char_counts=[0]*256;tag_counts=[0]*16;outcomes={};aliased=0
regs=[UC_ARM64_REG_X19,UC_ARM64_REG_X20,UC_ARM64_REG_X21,UC_ARM64_REG_X22,UC_ARM64_REG_X23,UC_ARM64_REG_X24,UC_ARM64_REG_X25,UC_ARM64_REG_X26,UC_ARM64_REG_X27,UC_ARM64_REG_X28,UC_ARM64_REG_X29,UC_ARM64_REG_D8,UC_ARM64_REG_D9,UC_ARM64_REG_D10,UC_ARM64_REG_D11,UC_ARM64_REG_D12,UC_ARM64_REG_D13,UC_ARM64_REG_D14,UC_ARM64_REG_D15]
edges=[0,1,0x7ffffffe,0x7fffffff,0x80000000,0xffffffff,0x100000000,0x7fffffffffffffff,0x8000000000000000,0xffffffffffffffff]
for case in range(cases):
 data=bytearray(rng.randbytes(0x1000));sp=STACK+0x2000;fpsr=case%4;fpcr=((case//4)%4)<<22
 if LANE=='presentation':
  cursor=BASE+0x200+(case//256)%16;p=BASE+0x400+(case//4096);spec=BASE+0x100
  layout=(case//4096)%4
  if layout==1:spec=cursor-1
  elif layout==2:spec=p-1
  elif layout==3:spec=cursor+(case%17)-8
  struct.pack_into('<Q',data,cursor-BASE,p);data[p-BASE]=case%256
  char_counts[data[p-BASE]]+=1;aliased+=int(layout!=0)
  args=[spec,cursor]
 else:
  v=BASE+0x400+(case//16)%16;tag=case%16;tag_counts[tag]+=1
  val=edges[(case//16)%len(edges)] if case<4096 else rng.getrandbits(64)
  struct.pack_into('<Q',data,v-BASE,val);data[v-BASE+16]=tag;args=[rng.getrandbits(64),v]
 saved=[rng.getrandbits(64) for _ in regs]
 ref.mem_write(BASE,bytes(data));ref.mem_write(STACK,bytes([0xa5])*0x4000)
 for reg,x in zip(regs,saved):ref.reg_write(reg,x)
 for reg,x in [(UC_ARM64_REG_SP,sp),(UC_ARM64_REG_X0,args[0]),(UC_ARM64_REG_X1,args[1]),(UC_ARM64_REG_X30,STOP),(UC_ARM64_REG_FPSR,fpsr),(UC_ARM64_REG_FPCR,fpcr)]:ref.reg_write(reg,x)
 state.clear();ref.emu_start(start,STOP,count=200);is_error=state.get('error',False)
 if not is_error:
  assert ref.reg_read(UC_ARM64_REG_PC)==STOP
  assert ref.reg_read(UC_ARM64_REG_SP)==sp
  assert [ref.reg_read(r) for r in regs]==saved
 wanted_mem=bytes(ref.mem_read(BASE,len(data)))
 wanted_value=[ref.reg_read(UC_ARM64_REG_X0),0x8b4614 if is_error else 0]
 outcome=hex(wanted_value[0]) if is_error else 'return';outcomes[outcome]=outcomes.get(outcome,0)+1
 for oi,(u,entry,_) in enumerate(engines):
  u.mem_write(BASE,bytes(data));u.mem_write(STACK,bytes(0x4000));u.mem_write(0x3300000,bytes(0x1000))
  for reg,x in zip(regs,saved):u.reg_write(reg,x)
  callargs=args if LANE=='presentation' else [args[1],0x3300000]
  for reg,x in [(UC_ARM64_REG_SP,sp),(UC_ARM64_REG_X0,callargs[0]),(UC_ARM64_REG_X1,callargs[1]),(UC_ARM64_REG_X30,STOP),(UC_ARM64_REG_FPSR,fpsr),(UC_ARM64_REG_FPCR,fpcr)]:u.reg_write(reg,x)
  u.emu_start(entry,STOP,count=5000)
  ok=bytes(u.mem_read(BASE,len(data)))==wanted_mem and u.reg_read(UC_ARM64_REG_PC)==STOP and u.reg_read(UC_ARM64_REG_SP)==sp and [u.reg_read(r) for r in regs]==saved and u.reg_read(UC_ARM64_REG_FPSR)==ref.reg_read(UC_ARM64_REG_FPSR) and u.reg_read(UC_ARM64_REG_FPCR)==ref.reg_read(UC_ARM64_REG_FPCR)
  if LANE=='numeric':ok=ok and list(struct.unpack('<QQ',bytes(u.mem_read(0x3300000,16))))==wanted_value
  passes[oi]+=int(ok)
  if not ok and len(failures)<10:failures.append({'case':case,'optimization':oi,'original_error':is_error,'original_transfer':wanted_value})
codeoff=va_to_offset(original,start);code=original[codeoff:codeoff+end-start]
report={'original_image_sha256':sha(original),'original_entry':hex(start),'compiler_adjacent_end':hex(end),'original_envelope_bytes':len(code),'original_envelope_sha256':sha(code),'lane':LANE,'cases':cases,'passes_O0_O2_O3':passes,'comparisons':cases*3,'mismatches':cases*3-sum(passes),'failures':failures,'original_instruction_locations':list(map(hex,sorted(covered))),'original_instruction_count':len(covered),'input_byte_counts':char_counts if LANE=='presentation' else None,'tag_counts':tag_counts if LANE=='numeric' else None,'overlap_cases':aliased,'outcomes':outcomes,'source_sha256':sha(SOURCE.encode()),'module_sha256':[x[2] for x in engines],'whole_function_bounded_tests_passed':LANE=='presentation' and sum(passes)==cases*3,'all_input_equivalence_proven':False,'whole_payload_verified':False,'limits':['Presentation lane compares entry-to-return behavior, complete modeled public memory, callee-saved registers, SP, FPCR and FPSR for all 256 input bytes and sampled overlapping buffers. Memory faults, concurrency and MMIO excluded.','Numeric lane covers tags 0..15 only. Stops before original error calls; reports exact error message and target without executing or stubbing any callee. Does not establish throwing/unwind semantics or arbitrary-tag behavior.','Full original image SHA and original slice hashes retained. No additional decompiler profile.']}
(OUT/'verification.json').write_text(json.dumps(report,indent=2));print(json.dumps(report,indent=2));assert not report['mismatches']
