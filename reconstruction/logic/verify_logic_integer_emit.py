"""Actual callable source ABI; real original helper execution; cuts before unresolved externals."""
import pathlib,struct,json,random,subprocess,os,hashlib
from unicorn import UC_HOOK_CODE
from unicorn.arm64_const import *
ROOT=pathlib.Path.cwd();parent=(ROOT/'prior/verify_logic_tail_adapters.py').read_text();exec(parent[:parent.index('archive = ARCHIVE.read_bytes()')]);ROOT=pathlib.Path.cwd()
LANE=os.environ['REA_LANE'];assert LANE in ['emitter','visitor-output'];OUT=ROOT/('integer-emission-'+LANE);OUT.mkdir(exist_ok=True)
original=(ROOT/'dossiers/logic-input/target.bin').read_bytes();assert sha(original)==EXPECTED_LOGIC
SOURCE=(ROOT/'reconstruction/logic/logic_integer_emit_candidate.c').read_text();(OUT/'logic_integer_emit_candidate.c').write_text(SOURCE)
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
 for argv in (["clang-18","-target","arm64-apple-ios17.0",f'-O{opt}',"-ffreestanding","-fno-builtin","-fno-stack-protector","-Wall","-Wextra","-Werror","-I",str(ROOT/'reconstruction/logic'),"-c",str(OUT/'logic_integer_emit_candidate.c'),'-o',str(obj)],['ld64.lld-18','-arch','arm64','-platform_version','ios','17.0','17.0','-dylib','-undefined','dynamic_lookup',str(obj),'-o',str(lib)]):
  r=subprocess.run(argv,text=True,capture_output=True);diags.append({'argv':argv,'returncode':r.returncode,'stderr':r.stderr});(OUT/'compile.json').write_text(json.dumps(diags,indent=2));assert r.returncode==0,r.stderr
 raw=lib.read_bytes();u,syms=engine(raw);entry=next(v for n,v,undefined in syms if n==('_logic_integer_output_original_8c05bc' if LANE=='emitter' else '_logic_complete_tag3_visitor') and not undefined);im,_=metadata(raw)
 assert set(im.values())<={'_memcpy','_memmove','_memset','_logic_format_error_original_8b4614','_logic_flag_error_original_8bfc08','_logic_presentation_error_original_8b5ab0','_logic_locale_emitter_original_8c070c'},im
 st={'callback_entry':next(v for n,v,undefined in syms if n=='_logic_hex_upper' and not undefined)};blr={}
 for vm,vs,off,fs in macho(raw)[0]:
  for at in range(off,off+fs-3,4):
   word=struct.unpack_from('<I',raw,at)[0]
   if word&0xfffffc1f==0xd63f0000:blr[vm+at-off]=(word>>5)&31
 st['blr']=blr
 def compiled_hook(u,pc,n,st):
  if pc in st['imports']:
   name=st['imports'][pc];st['cut']={'_memcpy':'memcpy','_memmove':'memmove','_memset':'memset','_logic_format_error_original_8b4614':'error','_logic_flag_error_original_8bfc08':'flag','_logic_presentation_error_original_8b5ab0':'presentation','_logic_locale_emitter_original_8c070c':'locale'}[name];u.emu_stop();return
  if pc in st['blr']:
   rn=st['blr'][pc];target=u.reg_read(globals()[f'UC_ARM64_REG_X{rn}'])
   if target==st['callback_entry']:st['transform_calls']=st.get('transform_calls',0)+1;return
   st['growth_target']=target;st['cut']='grow';u.emu_stop()
 st['imports']=im;u.hook_add(UC_HOOK_CODE,compiled_hook,st);engines.append((u,entry,sha(raw),st))


ref,_=engine(original);state={};covered=set();calls={};grows={0x8b87b4,0x8b889c,0x8b8bdc,0x8b8c9c,0x8b89b4,0x8b8ac0,0x8c0b3c};callbacks={id(u):st['callback_entry'] for u,_,_,st in engines}
ranges=[(0x8b47a0,0x8b4e44),(0x8b5060,0x8b51b4),(0x8b586c,0x8b5ab0),(0x8b5be4,0x8b5d84),(0x8be270,0x8be92c),(0x8ba1c0,0x8ba3b4),(0x8b86dc,0x8b90b0),(0x8c05bc,0x8c0d40),(0x8c0d8c,0x8c1144)]
cutmap={0xf0bfe8:'memcpy',0xf0bff4:'memmove',0xf0c000:'memset',0x8b4614:'error',0x8bfc08:'flag',0x8b5ab0:'presentation'}
def ref_hook(u,pc,n,_):
 if pc in cutmap:state['cut']=cutmap[pc];u.emu_stop();return
 if pc==0x8c070c and u.reg_read(UC_ARM64_REG_X2)&64:state['cut']='locale';u.emu_stop();return
 if pc in [0x8b89e0,0x8b8af0]:assert u.reg_read(UC_ARM64_REG_X20)==0x8b88d0;state['transform_calls']=state.get('transform_calls',0)+1
 if pc in grows:state['cut']='grow';state['growth_target']=u.reg_read(UC_ARM64_REG_X8);u.emu_stop();return
 assert any(a<=pc<b for a,b in ranges),hex(pc);covered.add(pc)
 if pc in [0x8b5060,0x8b586c,0x8b5be4,0x8be270,0x8be304,0x8ba1c0,0x8be44c,0x8be770,0x8b47a0,0x8be83c,0x8c05bc,0x8c070c,0x8c0d8c,0x8b86dc,0x8b88e8,0x8b8b0c]:calls[hex(pc)]=calls.get(hex(pc),0)+1
ref.hook_add(UC_HOOK_CODE,ref_hook)
regs=list(range(UC_ARM64_REG_X19,UC_ARM64_REG_X28+1))+[UC_ARM64_REG_X29]+[UC_ARM64_REG_D8,UC_ARM64_REG_D9,UC_ARM64_REG_D10,UC_ARM64_REG_D11,UC_ARM64_REG_D12,UC_ARM64_REG_D13,UC_ARM64_REG_D14,UC_ARM64_REG_D15]
rng=random.Random(0x8c05bc+len(LANE));passes=[0,0,0];failures=[];cases=16384;outcomes={};callback_total=0;written_return_bytes=0
texts=[b'X}',b'#X}',b'+X}',b' X}',b'>8X}',b'8X}',b'08X}',b'{0}X}',b'{}X}',b'{2}X}',b'd}',b'b}',b'B}',b'x}',b'o}',b'c}',b'LX}',b'\xc2\x80<8X}',b'{<',b'\xff}',b'64X}',b'2147483648X}',b's}',b'?}',b'P}',b'{:}',b'+c}',b'#c}',b'0c}',b'<c}',b'}',b'']
values=[0,1,127,128,255,256,0x7fffffff,0x80000000,0xffffff80,0xffffff7f,0xffffffff];dynamicvalues=[0,1,2,8,16,32,64,0x80000000,0xffffffff,0x8000000000000000];fills=[32,46,0xa2c2,0xac82e2,0x80989ff0]
def observed(u,st):
 kind=st.get('cut','return');a=[u.reg_read(r) for r in [UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3,UC_ARM64_REG_X4,UC_ARM64_REG_X5,UC_ARM64_REG_X6,UC_ARM64_REG_X7]]
 if kind=='return':return (kind,a[:1])
 if kind=='grow':return (kind,[st['growth_target']]+a[:2])
 if kind in ['error','presentation']:return (kind,a[:1])
 if kind=='flag':return (kind,a[:2])
 if kind=='locale':
  assert STACK<=a[5]<a[6]<=STACK+0x4000
  prefix=None if not a[7] else bytes(u.mem_read(a[7],4)).split(b'\0')[0].hex()
  base=struct.unpack('<I',bytes(u.mem_read(u.reg_read(UC_ARM64_REG_SP),4)))[0]
  return (kind,[a[0]&0xffffffff,a[1],a[2],a[3],a[4]&0xffffffff,a[6]-a[5],prefix,base])
 if kind=='memset':return (kind,[a[0],a[1]&0xffffffff,a[2]])
 dest,src,length=a[:3];assert 0<length<=128
 destrole=dest
 if STACK<=dest<STACK+0x4000:
  assert STACK<=dest-12 and dest+4<=STACK+0x4000 and length<=4
  destrole=['private-spec-fill',bytes(u.mem_read(dest-12,16)).hex()]
 srcrole=src
 if STACK<=src<STACK+0x4000:
  assert src+length<=STACK+0x4000;srcrole=['private-payload',bytes(u.mem_read(src,length)).hex()]
 return (kind,[destrole,srcrole,length])
start=0x8c05bc if LANE=='emitter' else 0x8b493c
for case in range(cases):
 data=bytearray(rng.randbytes(0x8000));align=case%16;ctx=BASE+0x100+align;parse=BASE+0x400+align;fmt=BASE+0x800+align;flagptr=BASE+0xc00;valueptr=BASE+0xd00+align;p=BASE+0x1000+align;argsbuf=BASE+0x1800+align;out=BASE+0x3000;limit=BASE+0x3200;buf=BASE+0x4000;callback=0x6000000+(case%16)*4
 count=[0,1,4,12,13,32][case%6];packed=0
 for j in range(count):
  tag=(case+j)%16;value=dynamicvalues[(case//16+j)%len(dynamicvalues)];stride=16 if count<=12 else 32;struct.pack_into('<QQ',data,argsbuf-BASE+j*stride,value,rng.getrandbits(64))
  if count<=12:packed|=tag<<(5*j)
  else:data[argsbuf-BASE+j*stride+16]=tag
 struct.pack_into('<QQQQ',data,fmt-BASE,out,count,argsbuf,packed)
 text=texts[case%len(texts)]
 if case>=8192:text=bytes(rng.choice(b'0123456789{}.:x+ #0<>^Lndf?cBX') for _ in range(rng.randrange(25)))
 length=len(text);flag=[0,1,2,255][(case//6)%4];value32=values[(case//4)%len(values)] if case<8192 else rng.getrandbits(32)
 cap=[0,1,8,16,32,64,128][case%7];pos=rng.randrange(cap+1);haslimit=case%3!=0
 if LANE=='visitor-output' and case<256:text=b'X}';length=2;flag=1;cap=128;pos=0;haslimit=False
 data[p-BASE:p-BASE+len(text)]=text;struct.pack_into('<QQI',data,parse-BASE,p,p+length,(case//6)%5);struct.pack_into('<Q',data,parse-BASE+24,rng.choice([0,1,2,0xffffffff,rng.randrange(35)]));struct.pack_into('<QQQ',data,ctx-BASE,parse,fmt,flagptr);data[flagptr-BASE]=flag;struct.pack_into('<I',data,valueptr-BASE,value32);data[valueptr-BASE+16]=3
 width=rng.randrange(-16,65);first=((width&0xffffffff)<<32)|rng.getrandbits(32);first&=~64;second=(fills[(case//7)%len(fills)]<<32)|rng.getrandbits(32);negative=case%4
 if LANE=='emitter' and case%4==0:first=0x700;cap=128;pos=0;haslimit=False
 elif LANE=='emitter' and case%16==15:first|=64
 struct.pack_into('<QQQQQ',data,out-BASE,buf,cap,pos,callback,limit if haslimit else 0);end=rng.randrange(129);used=rng.choice([0,end,end+1,0xffffffffffffffff,rng.randrange(129)]);struct.pack_into('<QQ',data,limit-BASE,end,used)
 guard=BASE+0x7f00;struct.pack_into('<Q',data,guard-BASE,rng.getrandbits(64));ref.mem_write(0x1297340,struct.pack('<Q',guard))
 args=[value32,fmt,first,second,negative] if LANE=='emitter' else [ctx,valueptr]
 saved=[rng.getrandbits(64) for _ in regs];sp=STACK+0x3000;fpsr=case%4;fpcr=((case//4)%4)<<22
 def initialize(u):
  u.mem_write(BASE,bytes(data));u.mem_write(STACK,bytes([0xa5])*0x4000)
  for r,v in zip(regs,saved):u.reg_write(r,v)
  for r,v in zip([UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3,UC_ARM64_REG_X4],args):u.reg_write(r,v)
  for r,v in [(UC_ARM64_REG_X30,STOP),(UC_ARM64_REG_SP,sp),(UC_ARM64_REG_FPSR,fpsr),(UC_ARM64_REG_FPCR,fpcr)]:u.reg_write(r,v)
 initialize(ref);state.clear();ref.emu_start(start,STOP,count=20000);assert state.get('cut') or ref.reg_read(UC_ARM64_REG_PC)==STOP,('original_budget',case,hex(ref.reg_read(UC_ARM64_REG_PC)));wanted=observed(ref,state);callback_total+=state.get('transform_calls',0);memory=bytes(ref.mem_read(BASE,len(data)))
 if wanted[0]=='return':
  assert ref.reg_read(UC_ARM64_REG_SP)==sp and [ref.reg_read(r) for r in regs]==saved
  written_return_bytes+=sum(a!=b for a,b in zip(memory[buf-BASE:buf-BASE+256],data[buf-BASE:buf-BASE+256]))
 for oi,(u,entry,_,st) in enumerate(engines):
  initialize(u);st.pop('cut',None);st.pop('growth_target',None);st.pop('transform_calls',None);u.emu_start(entry,STOP,count=500000);assert st.get('cut') or u.reg_read(UC_ARM64_REG_PC)==STOP,('compiled_budget',case,oi,hex(u.reg_read(UC_ARM64_REG_PC)));got=observed(u,st)
  ok=got==wanted and bytes(u.mem_read(BASE,len(data)))==memory and st.get('transform_calls',0)==state.get('transform_calls',0) and u.reg_read(UC_ARM64_REG_FPSR)==ref.reg_read(UC_ARM64_REG_FPSR) and u.reg_read(UC_ARM64_REG_FPCR)==ref.reg_read(UC_ARM64_REG_FPCR)
  if got[0]=='return':ok=ok and u.reg_read(UC_ARM64_REG_SP)==sp and [u.reg_read(r) for r in regs]==saved
  passes[oi]+=int(ok)
  if not ok and len(failures)<25:failures.append({'case':case,'text':text.hex(),'flag':flag,'value32':value32,'first':hex(first),'second':hex(second),'negative':negative,'capacity':cap,'position':pos,'has_limit':haslimit,'limit_end':end,'limit_used':used,'opt':[0,2,3][oi],'expected':wanted,'actual':got,'memory_equal':bytes(u.mem_read(BASE,len(data)))==memory,'callback_counts':[state.get('transform_calls',0),st.get('transform_calls',0)]})
 key=wanted[0]+(':'+hex(wanted[1][1 if wanted[0]=='flag' else 0]) if wanted[0] in ['error','flag'] else '');outcomes[key]=outcomes.get(key,0)+1
report={'image_sha256':sha(original),'entry':hex(start),'lane':LANE,'cases':cases,'comparisons':cases*3,'passes_O0_O2_O3':passes,'mismatches':cases*3-sum(passes),'failures':failures,'outcomes':outcomes,'actual_original_helper_calls':calls,'actual_original_uppercase_callback_calls':callback_total,'changed_output_bytes_in_returned_original_cases':written_return_bytes,'original_instruction_count':len(covered),'original_instruction_locations':list(map(hex,sorted(covered))),'source_sha256':sha(SOURCE.encode()),'included_source_sha256':{name:sha((ROOT/'reconstruction/logic'/name).read_bytes()) for name in ['logic_integer_digits.c','logic_buffer_transform_candidate.c','logic_buffer_output_candidate.c','logic_integer_path_candidate.c','logic_format_core_candidate.c','logic_format_validate_candidate.c']},'module_sha256':[e[2] for e in engines],'actual_function_ABI_source':True,'whole_function_verified':False,'all_input_equivalence_proven':False,'limits':['Uninterrupted original visitor/formatter/parser/resolver/emitter/digit/padding/transformed-writer/real-uppercase-callback execution, including successful output returns. No fake callee or successful callback installed.','Stop before real memcpy/memmove/memset, throwing helpers or indirect growth BLR. Locale branch preserves exact real original emitter-entry dependency and original 9-argument ABI, including bounded private buffer capacity and prefix contents; locale body unverified.','Compare complete public context/spec/arguments/output memory, return ABI and full saved state/SP/FPCR/FPSR; original callback count matches real compiled source callback per case. Private copy pointers normalize to complete relevant object/payload contents; public pointers retained.','Original guards use allocated ordinary modeled process-canary storage; corruption/abort excluded. Fixed output width <=64 on ordinary paths, dynamic numeric values valid<=64 or explicit error values, tags0..15, bounded disjoint buffers and mapped strings. Locale/runtime/growth bodies, faults, arbitrary aliases, concurrency and whole-payload correctness remain unresolved.']}
(OUT/'verification.json').write_text(json.dumps(report,indent=2));print(json.dumps(report,indent=2));assert not report['mismatches']
