"""Actual callable source ABI; real original helper execution; cuts before unresolved externals."""
import pathlib,struct,json,random,subprocess,os,hashlib
from unicorn import UC_HOOK_CODE
from unicorn.arm64_const import *
ROOT=pathlib.Path.cwd();parent=(ROOT/'prior/verify_logic_tail_adapters.py').read_text();exec(parent[:parent.index('archive = ARCHIVE.read_bytes()')]);ROOT=pathlib.Path.cwd()
LANE=os.environ['REA_LANE'];assert LANE in ['resolve-errors','signed-int','visitor-tag3'];OUT=ROOT/('integer-path-'+LANE);OUT.mkdir(exist_ok=True)
original=(ROOT/'dossiers/logic-input/target.bin').read_bytes();assert sha(original)==EXPECTED_LOGIC
SOURCE=(ROOT/'reconstruction/logic/logic_integer_path_candidate.c').read_text();(OUT/'logic_integer_path_candidate.c').write_text(SOURCE)
def metadata(b):
 pos=32;sections=[];ind=None;sym=None;stream=None;base=None
 for _ in range(struct.unpack_from('<I',b,16)[0]):
  cmd,n=struct.unpack_from('<II',b,pos)
  if cmd==2:sym=struct.unpack_from('<IIII',b,pos+8)
  if cmd==11:ind=struct.unpack_from('<II',b,pos+56)
  if cmd==0x26:
   off,size=struct.unpack_from('<II',b,pos+8);stream=b[off:off+size]
  if cmd==25:
   if b[pos+8:pos+24].split(b'\0')[0]==b'__TEXT':base=struct.unpack_from('<Q',b,pos+24)[0]
   for j in range(struct.unpack_from('<I',b,pos+64)[0]):
    at=pos+72+j*80;va,size=struct.unpack_from('<QQ',b,at+32);flags,ri,stride=struct.unpack_from('<III',b,at+64)
    if flags&255==8:sections.append((va,size,ri,stride))
  pos+=n
 imports={};starts=[]
 if ind and sym:
  so,count,st,sz=sym
  for va,size,ri,stride in sections:
   for j in range(size//stride):
    idx=struct.unpack_from('<I',b,ind[0]+4*(ri+j))[0]
    if idx&0xc0000000:continue
    si=struct.unpack_from('<I',b,so+16*idx)[0];name=b[st+si:b.index(b'\0',st+si)].decode();imports[va+j*stride]=name
 if stream is not None:
  a=base;v=shift=0
  for byte in stream:
   v|=(byte&127)<<shift
   if byte&128:shift+=7;continue
   if not v:break
   a+=v;starts.append(a);v=shift=0
 return imports,starts
engines=[];diags=[]
for opt in (0,2,3):
 obj=OUT/f'O{opt}.o';lib=OUT/f'O{opt}.dylib'
 for argv in (["clang-18","-target","arm64-apple-ios17.0",f'-O{opt}',"-ffreestanding","-fno-builtin","-fno-stack-protector","-Wall","-Wextra","-Werror","-I",str(ROOT/'reconstruction/logic'),"-c",str(OUT/'logic_integer_path_candidate.c'),'-o',str(obj)],['ld64.lld-18','-arch','arm64','-platform_version','ios','17.0','17.0','-dylib','-undefined','dynamic_lookup',str(obj),'-o',str(lib)]):
  r=subprocess.run(argv,text=True,capture_output=True);diags.append({'argv':argv,'returncode':r.returncode,'stderr':r.stderr});(OUT/'compile.json').write_text(json.dumps(diags,indent=2));assert r.returncode==0,r.stderr
 raw=lib.read_bytes();u,syms=engine(raw);entry=next(v for n,v,undefined in syms if n=={'resolve-errors':'_logic_resolved_specs_expanded','signed-int':'_logic_signed_integer_format','visitor-tag3':'_logic_tag3_visitor'}[LANE] and not undefined);im,_=metadata(raw)
 assert set(im.values())<={'_memmove','_logic_format_error_original_8b4614','_logic_flag_error_original_8bfc08','_logic_presentation_error_original_8b5ab0','_logic_integer_output_original_8c05bc','_logic_character_output_original_8b86dc'},im
 st={}
 def compiled_hook(u,pc,n,st):
  if pc in st['imports']:
   name=st['imports'][pc];st['cut']={'_memmove':'memmove','_logic_format_error_original_8b4614':'error','_logic_flag_error_original_8bfc08':'flag','_logic_presentation_error_original_8b5ab0':'presentation','_logic_integer_output_original_8c05bc':'integer-output','_logic_character_output_original_8b86dc':'character-output'}[name];u.emu_stop()
 st['imports']=im;u.hook_add(UC_HOOK_CODE,compiled_hook,st);engines.append((u,entry,sha(raw),st))

ref,_=engine(original);state={};covered=set();calls={}
cutmap={0x8b4614:'error',0xf0bff4:'memmove',0x8bfc08:'flag',0x8b5ab0:'presentation',0x8c05bc:'integer-output',0x8b86dc:'character-output'}
ranges=[(0x8b47a0,0x8b493c),(0x8b493c,0x8b4e44),(0x8b5060,0x8b51b4),(0x8b586c,0x8b5ab0),(0x8b5be4,0x8b5d84),(0x8be270,0x8be92c),(0x8ba1c0,0x8ba3b4)]
def ref_hook(u,pc,n,_):
 if pc in cutmap:state['cut']=cutmap[pc];u.emu_stop();return
 assert any(a<=pc<b for a,b in ranges),hex(pc);covered.add(pc)
 if pc in [0x8b5060,0x8b586c,0x8b5be4,0x8be270,0x8be304,0x8ba1c0,0x8be44c,0x8be5bc,0x8be770,0x8b47a0,0x8be83c]:calls[hex(pc)]=calls.get(hex(pc),0)+1
ref.hook_add(UC_HOOK_CODE,ref_hook)
regs=list(range(UC_ARM64_REG_X19,UC_ARM64_REG_X28+1))+[UC_ARM64_REG_X29]+[UC_ARM64_REG_D8,UC_ARM64_REG_D9,UC_ARM64_REG_D10,UC_ARM64_REG_D11,UC_ARM64_REG_D12,UC_ARM64_REG_D13,UC_ARM64_REG_D14,UC_ARM64_REG_D15]
rng=random.Random(0x8b5060+len(LANE));passes=[0,0,0];failures=[];outcomes={};cases=24576
texts=[b'',b'}',b':',b'<',b'>',b'^',b'+',b'-',b' ',b'#',b'0',b'1',b'8',b'2147483647',b'2147483648',b'.',b'.0',b'{}',b'{0}',b'{1}',b'{2}',b'{2147483647}',b'{01}',b'{:}',b'{x}',b'<+#010LnX}',b'*^+#08d}',b'\xc2\x80<8d}',b'{<',b'\xff}',b'8Lx}',b'10xQ',b'c}',b'<c}',b'+c}',b'#c}',b'0c}',b'8c}',b'{0}c}',b'{0}d}',b'{}d}',b'{2}X}',b's}',b'f}',b'?}',b'P}',b'B}',b'X}',b'n}']
values=[0,1,127,128,255,256,0x7fffffff,0x80000000,0xffffff80,0xffffff7f,0xffffffff]
rawedges=[0,1,0x7fffffff,0x80000000,0xffffffff,0x100000000,0x7fffffffffffffff,0x8000000000000000,0xffffffffffffffff]
def observed(u,st):
 kind=st.get('cut','return')
 if kind=='return':return (kind,[u.reg_read(UC_ARM64_REG_X0),u.reg_read(UC_ARM64_REG_X1)])
 if kind=='character-output':return (kind,[bytes(u.mem_read(u.reg_read(UC_ARM64_REG_X0),1)).hex()]+[u.reg_read(r) for r in [UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3,UC_ARM64_REG_X4,UC_ARM64_REG_X5]])
 if kind=='memmove':
  dest=u.reg_read(UC_ARM64_REG_X0);src=u.reg_read(UC_ARM64_REG_X1);length=u.reg_read(UC_ARM64_REG_X2)
  if STACK<=dest<STACK+0x4000:
   assert STACK<=dest-12 and dest+4<=STACK+0x4000 and 1<=length<=4
   return (kind,['private-spec-fill',bytes(u.mem_read(dest-12,16)).hex(),src,length])
 n={'error':1,'presentation':1,'flag':2,'memmove':3,'integer-output':5}[kind]
 return (kind,[u.reg_read(r) for r in [UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3,UC_ARM64_REG_X4][:n]])
start={'resolve-errors':0x8b5be4,'signed-int':0x8b5060,'visitor-tag3':0x8b493c}[LANE]
for case in range(cases):
 data=bytearray(rng.randbytes(0x4000));align=case%16;ctx=BASE+0x100+align;parse=BASE+0x400+align;fmt=BASE+0x800+align;flagptr=BASE+0xc00;valueptr=BASE+0xd00+align;p=BASE+0x1000+align;argsbuf=BASE+0x1800+align;spec=BASE+0x200+align
 count=[0,1,4,12,13,32][case%6];packed=0
 for j in range(count):
  tag=(case+j)%16;value=rawedges[(case//16+j)%len(rawedges)] if case<16384 else rng.getrandbits(64);stride=16 if count<=12 else 32
  struct.pack_into('<QQ',data,argsbuf-BASE+j*stride,value,rng.getrandbits(64))
  if count<=12:packed|=tag<<(5*j)
  else:data[argsbuf-BASE+j*stride+16]=tag
 struct.pack_into('<QQQQ',data,fmt-BASE,BASE+0x3500,count,argsbuf,packed)
 text=texts[case%len(texts)]
 if case>=16384:text=bytes(rng.choice(b'0123456789{}.:x+ #0<>^Lndf?cBX') for _ in range(rng.randrange(25)))
 length=len(text) if case<16384 else rng.randrange(len(text)+1);data[p-BASE:p-BASE+len(text)]=text
 struct.pack_into('<QQI',data,parse-BASE,p,p+length,(case//6)%5);struct.pack_into('<Q',data,parse-BASE+24,rng.choice([0,1,2,0xffffffff,rng.randrange(35)]))
 struct.pack_into('<QQQ',data,ctx-BASE,parse,fmt,flagptr);flag=[0,1,2,255][(case//6)%4];data[flagptr-BASE]=flag
 value32=values[(case//4)%len(values)] if case<16384 else rng.getrandbits(32);struct.pack_into('<I',data,valueptr-BASE,value32);data[valueptr-BASE+16]=3
 mode=(case//6)%4;struct.pack_into('<H',data,spec-BASE+2,rng.randrange(0x4000)|(mode<<14))
 for off,dyn in [(4,mode&1),(8,mode&2)]:
  val=rng.choice([0,1,max(count-1,0),count,count+1,0xffffffff,0x80000000]) if dyn else rng.getrandbits(32);struct.pack_into('<I',data,spec-BASE+off,val)
 guard=BASE+0x3f00;struct.pack_into('<Q',data,guard-BASE,rng.getrandbits(64));ref.mem_write(0x1297340,struct.pack('<Q',guard))
 args=[spec,fmt] if LANE=='resolve-errors' else [ctx,valueptr if LANE=='visitor-tag3' else value32|(rng.getrandbits(32)<<32)]
 saved=[rng.getrandbits(64) for _ in regs];sp=STACK+0x3000;fpsr=case%4;fpcr=((case//4)%4)<<22
 def initialize(u):
  u.mem_write(BASE,bytes(data));u.mem_write(STACK,bytes([0xa5])*0x4000)
  for r,v in zip(regs,saved):u.reg_write(r,v)
  for r,v in [(UC_ARM64_REG_X0,args[0]),(UC_ARM64_REG_X1,args[1]),(UC_ARM64_REG_X30,STOP),(UC_ARM64_REG_SP,sp),(UC_ARM64_REG_FPSR,fpsr),(UC_ARM64_REG_FPCR,fpcr)]:u.reg_write(r,v)
 initialize(ref);state.clear();ref.emu_start(start,STOP,count=10000);wanted=observed(ref,state);memory=bytes(ref.mem_read(BASE,len(data)))
 if wanted[0]=='return':assert LANE=='resolve-errors' and ref.reg_read(UC_ARM64_REG_PC)==STOP and ref.reg_read(UC_ARM64_REG_SP)==sp and [ref.reg_read(r) for r in regs]==saved
 for oi,(u,entry,_,st) in enumerate(engines):
  initialize(u);st.pop('cut',None);u.emu_start(entry,STOP,count=30000);got=observed(u,st)
  ok=got==wanted and bytes(u.mem_read(BASE,len(data)))==memory and u.reg_read(UC_ARM64_REG_FPSR)==ref.reg_read(UC_ARM64_REG_FPSR) and u.reg_read(UC_ARM64_REG_FPCR)==ref.reg_read(UC_ARM64_REG_FPCR)
  if got[0]=='return':ok=ok and u.reg_read(UC_ARM64_REG_PC)==STOP and u.reg_read(UC_ARM64_REG_SP)==sp and [u.reg_read(r) for r in regs]==saved
  passes[oi]+=int(ok)
  if not ok and len(failures)<25:failures.append({'case':case,'text':text.hex(),'length':length,'flag':flag,'value32':value32,'mode':mode,'count':count,'opt':[0,2,3][oi],'expected':wanted,'actual':got,'memory_equal':bytes(u.mem_read(BASE,len(data)))==memory})
 key=wanted[0]+(':'+hex(wanted[1][1 if wanted[0]=='flag' else 0]) if wanted[0] in ['error','flag'] else '');outcomes[key]=outcomes.get(key,0)+1
report={'image_sha256':sha(original),'entry':hex(start),'lane':LANE,'cases':cases,'comparisons':cases*3,'passes_O0_O2_O3':passes,'mismatches':cases*3-sum(passes),'failures':failures,'outcomes':outcomes,'actual_original_helper_calls':calls,'original_instruction_count':len(covered),'original_instruction_locations':list(map(hex,sorted(covered))),'source_sha256':sha(SOURCE.encode()),'included_source_sha256':{name:sha((ROOT/'reconstruction/logic'/name).read_bytes()) for name in ['logic_format_core_candidate.c','logic_format_validate_candidate.c']},'module_sha256':[e[2] for e in engines],'rejected_parent_runs':[39900460000,39901106895],'private_stack_normalization':'For a memmove into the local spec fill field, compare its full 16-byte local spec snapshot, exact source pointer and length after checking stack bounds; compiler-private stack addresses may differ. No public pointer normalized.','harness_correction':'Admit the real original argument-ID helper range 0x8b47a0..0x8b493c previously omitted from the execution whitelist. Candidate C source unchanged.','actual_function_ABI_source':True,'whole_function_verified':False,'all_input_equivalence_proven':False,'limits':['Uninterrupted original execution through real visitor, formatter, central parser, validation, dynamic resolver, numeric and UTF8 helpers; stops before real output, memmove or throwing helpers. No successful fake callbacks or stub implementations.','Resolver expands prior valid-only domain to missing/out-of-range/negative indices, tags 0..15 and 64-bit numeric edge values with exact original errors. Tags outside 0..15 remain excluded.','Compare modeled public context/spec/argument memory, return ABI or exact output/error call arguments (character pointer normalized to its one-byte content), FPCR/FPSR and full callee-saved state/SP on returns.','Original native guard slot points to allocated synthetic process guard storage; guard corruption/abort excluded. Ordinary disjoint memory and bounded strings; no real output execution, exceptions, unwind, arbitrary aliases, faults or concurrency claim.']}
(OUT/'verification.json').write_text(json.dumps(report,indent=2));print(json.dumps(report,indent=2));assert not report['mismatches']
