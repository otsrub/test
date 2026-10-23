"""Width/precision parser source slices through return or first real helper/error call."""
import pathlib,os,json,struct,random,subprocess
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
from unicorn.arm64_const import *
ROOT=pathlib.Path.cwd();parent=(ROOT/'prior/verify_logic_tail_adapters.py').read_text()
exec(parent[:parent.index('archive = ARCHIVE.read_bytes()')]);ROOT=pathlib.Path.cwd()
LANE=os.environ['REA_LANE'];assert LANE in ('width','precision')
OUT=ROOT/('decimal-'+LANE);OUT.mkdir(exist_ok=True)
original=(ROOT/'dossiers/logic-input/target.bin').read_bytes();assert sha(original)==EXPECTED_LOGIC
SOURCE=r'''
#include <stdint.h>
static uint64_t rd(const unsigned char*p,unsigned n){uint64_t x=0;for(unsigned i=0;i<n;i++)x|=(uint64_t)p[i]<<(8*i);return x;}
static void wr(unsigned char*p,uint64_t x,unsigned n){for(unsigned i=0;i<n;i++)p[i]=(unsigned char)(x>>(8*i));}
static unsigned ch(uint64_t p){return *(const unsigned char*)(uintptr_t)p;}
void logic_decimal(unsigned char *spec,unsigned char *cursor,uint64_t end,
                   uint64_t parsectx,unsigned precision,uint64_t out[5]){
 uint64_t p=rd(cursor,8),q=p,msg=0,target=0,arg=0,ret=0;unsigned c=ch(p);
 if(precision){if(c!='.')goto done;q=p+1;wr(cursor,q,8);if(q==end){msg=0x10929c9;goto error;}c=ch(q);}
 if(c=='{'){
  q++;wr(cursor,q,8);if(q==end){msg=0x109297e;goto error;}
  target=0x8b47a0;arg=q;out[0]=2;out[1]=target;out[2]=arg;out[3]=end;out[4]=parsectx;return;
 }
 if(c<'0'||c>'9'){if(precision){msg=0x10929ff;goto error;}goto done;}
 if(!precision&&c=='0'){msg=0x109294e;goto error;}
 uint64_t value=0;unsigned digits=0;
 do{
  value=value*10+ch(q)-'0';digits++;q++;
  if(value>0x7fffffffULL){msg=0x1092820;goto error;}
  if(q==end)break;
  c=ch(q);if(c<'0'||c>'9')break;
  if(digits==10){msg=0x1092820;goto error;}
 }while(1);
 wr(spec+(precision?8:4),value,4);
 if(precision)wr(spec+2,rd(spec+2,2)&0x7fff,2);
 wr(cursor,q,8);ret=1;
 done:out[0]=0;out[1]=0;out[2]=ret;out[3]=0;out[4]=0;return;
 error:out[0]=1;out[1]=0x8b4614;out[2]=msg;out[3]=0;out[4]=0;
}
'''
(OUT/'logic_decimal.c').write_text(SOURCE);engines=[];diags=[]
for opt in (0,2,3):
 obj=OUT/f'O{opt}.o';lib=OUT/f'O{opt}.dylib'
 for argv in (["clang-18","-target","arm64-apple-ios17.0",f'-O{opt}',"-ffreestanding","-fno-builtin","-Wall","-Wextra","-Werror","-c",str(OUT/'logic_decimal.c'),'-o',str(obj)],['ld64.lld-18','-arch','arm64','-platform_version','ios','17.0','17.0','-dylib','-undefined','error',str(obj),'-o',str(lib)]):
  r=subprocess.run(argv,text=True,capture_output=True);diags.append({'argv':argv,'returncode':r.returncode,'stderr':r.stderr});(OUT/'compile.json').write_text(json.dumps(diags,indent=2));assert r.returncode==0,r.stderr
 raw=lib.read_bytes();u,syms=engine(raw);u.mem_map(0x3300000,0x1000);entry=next(v for n,v,undef in syms if n=='_logic_decimal' and not undef);engines.append((u,entry,sha(raw)))
start,end=(0x8be44c,0x8be5bc) if LANE=='width' else (0x8be5bc,0x8be770)
ref,_=engine(original);covered=set();state={}
sliceoff=va_to_offset(original,start);slicebytes=original[sliceoff:sliceoff+end-start]
def hook(u,pc,n,_):
 assert start<=pc<end,hex(pc)
 word=struct.unpack_from('<I',slicebytes,pc-start)[0]
 if word>>26==0b100101:
  imm=word&0x3ffffff;imm=imm-(1<<26) if imm&(1<<25) else imm
  state['target']=pc+imm*4;state['pc']=pc;u.emu_stop();return
 covered.add(pc)
ref.hook_add(UC_HOOK_CODE,hook);rng=random.Random(start);cases=0;passes=[0,0,0];failures=[];families={};outcomes={}
def inputs():
 for c in range(256):
  for n in [1,2,3,4]:yield ('all-leading-bytes',bytes([c])+b'7}x',n)
 for text in [b'0',b'1',b'9',b'10',b'2147483646',b'2147483647',b'2147483648',b'9999999999',b'0000000000',b'00000000000',b'10000000000',b'{',b'{}',b'{0}',b'{:}',b'{123}',b'.',b'.{',b'.{}',b'.{0}',b'.0',b'.2147483647',b'.2147483648',b'.00000000000']:
  for n in range(1,len(text)+1):yield ('decimal-and-brace-boundaries',text,n)
 for _ in range(12000):
  n=rng.randrange(1,15);s=bytes(rng.choice(b'0123456789{}.:x') for _ in range(n))
  if LANE=='precision' and rng.randrange(2):s=b'.'+s
  yield ('random-grammar',s,len(s))
regs=[UC_ARM64_REG_X19,UC_ARM64_REG_X20,UC_ARM64_REG_X21,UC_ARM64_REG_X22,UC_ARM64_REG_X23,UC_ARM64_REG_X24,UC_ARM64_REG_X25,UC_ARM64_REG_X26,UC_ARM64_REG_X27,UC_ARM64_REG_X28,UC_ARM64_REG_X29,UC_ARM64_REG_D8,UC_ARM64_REG_D9]
for case,(family,text,n) in enumerate(inputs()):
 data=bytearray(rng.randbytes(0x1000));spec=BASE+0x100+case%16;cursor=BASE+0x200+(case//16)%16;p=BASE+0x500+case%16;ctx=BASE+0x800;limit=p+n
 data[p-BASE:p-BASE+len(text)]=text;struct.pack_into('<Q',data,cursor-BASE,p)
 saved=[rng.getrandbits(64) for _ in regs];sp=STACK+0x2000;fpsr=case%4;fpcr=((case//4)%4)<<22
 ref.mem_write(BASE,bytes(data));ref.mem_write(STACK,bytes([0xa5])*0x4000)
 for r,x in zip(regs,saved):ref.reg_write(r,x)
 for r,x in [(UC_ARM64_REG_X0,spec),(UC_ARM64_REG_X1,cursor),(UC_ARM64_REG_X2,limit),(UC_ARM64_REG_X3,ctx),(UC_ARM64_REG_X30,STOP),(UC_ARM64_REG_SP,sp),(UC_ARM64_REG_FPSR,fpsr),(UC_ARM64_REG_FPCR,fpcr)]:ref.reg_write(r,x)
 state.clear();ref.emu_start(start,STOP,count=500)
 if 'target' not in state:
  assert ref.reg_read(UC_ARM64_REG_PC)==STOP;assert ref.reg_read(UC_ARM64_REG_SP)==sp and [ref.reg_read(r) for r in regs]==saved
  wanted=[0,0,ref.reg_read(UC_ARM64_REG_X0),0,0]
 else:
  target=state['target'];assert target in (0x8b4614,0x8b47a0)
  wanted=[1 if target==0x8b4614 else 2,target,ref.reg_read(UC_ARM64_REG_X0),0,0]
  if target==0x8b47a0:wanted[3:]=[ref.reg_read(UC_ARM64_REG_X1),ref.reg_read(UC_ARM64_REG_X2)]
 memory=bytes(ref.mem_read(BASE,len(data)))
 for oi,(u,entry,_) in enumerate(engines):
  u.mem_write(BASE,bytes(data));u.mem_write(STACK,bytes(0x4000));u.mem_write(0x3300000,bytes(0x1000))
  for r,x in zip(regs,saved):u.reg_write(r,x)
  for r,x in [(UC_ARM64_REG_X0,spec),(UC_ARM64_REG_X1,cursor),(UC_ARM64_REG_X2,limit),(UC_ARM64_REG_X3,ctx),(UC_ARM64_REG_X4,int(LANE=='precision')),(UC_ARM64_REG_X5,0x3300000),(UC_ARM64_REG_X30,STOP),(UC_ARM64_REG_SP,sp),(UC_ARM64_REG_FPSR,fpsr),(UC_ARM64_REG_FPCR,fpcr)]:u.reg_write(r,x)
  u.emu_start(entry,STOP,count=5000);got=list(struct.unpack('<5Q',bytes(u.mem_read(0x3300000,40))))
  ok=got==wanted and bytes(u.mem_read(BASE,len(data)))==memory and u.reg_read(UC_ARM64_REG_PC)==STOP and u.reg_read(UC_ARM64_REG_SP)==sp and [u.reg_read(r) for r in regs]==saved and u.reg_read(UC_ARM64_REG_FPCR)==ref.reg_read(UC_ARM64_REG_FPCR) and u.reg_read(UC_ARM64_REG_FPSR)==ref.reg_read(UC_ARM64_REG_FPSR)
  passes[oi]+=int(ok)
  if not ok and len(failures)<20:failures.append({'case':case,'text':text.hex(),'length':n,'opt':oi,'expected':wanted,'actual':got,'memory_equal':bytes(u.mem_read(BASE,len(data)))==memory})
 families[family]=families.get(family,0)+1;key='return' if not wanted[0] else hex(wanted[2]);outcomes[key]=outcomes.get(key,0)+1;cases+=1
report={'image_sha256':sha(original),'entry':hex(start),'lane':LANE,'cases':cases,'families':families,'comparisons':cases*3,'passes_O0_O2_O3':passes,'mismatches':cases*3-sum(passes),'failures':failures,'outcomes':outcomes,'original_instruction_count':len(covered),'original_instruction_locations':list(map(hex,sorted(covered))),'source_sha256':sha(SOURCE.encode()),'module_sha256':[x[2] for x in engines],'whole_function_verified':False,'limits':['Source state/transfer model compared with original entry-to-return or first real helper/error call. No callee executed or stubbed.','Static decimal and non-match paths execute to return. Dynamic brace paths stop before argument-id parser; exceptions/unwinding remain unresolved.','Input/spec/cursor are disjoint mapped ordinary memory with alignment varied. Logical input length >=1; faults, MMIO, concurrency and overlap excluded.']}
(OUT/'verification.json').write_text(json.dumps(report,indent=2));print(json.dumps(report,indent=2));assert not report['mismatches']
