import json, pathlib, random, struct, subprocess
from unicorn import UC_HOOK_CODE
from unicorn.arm64_const import *
ROOT=pathlib.Path.cwd();parent=(ROOT/'prior/verify_logic_tail_adapters.py').read_text();exec(parent[:parent.index('archive = ARCHIVE.read_bytes()')]);ROOT=pathlib.Path.cwd()
OUT=ROOT/'macore-png-fixed-caller';OUT.mkdir(exist_ok=True)
original=(ROOT/'dossiers/macore-input/target.bin').read_bytes();assert sha(original)=='88a8d93c6cb4b411648601efdfc5ca2863c3b833339e55e2470369df1d3bc9d5'
sources=['macore_png_fixed_caller.c','macore_png_filter_transforms.c','macore_png_paeth_transform.c']
source_hashes={}
for name in sources:
 raw=(ROOT/'reconstruction'/name).read_bytes();(OUT/name).write_bytes(raw);source_hashes[name]=sha(raw)

def imports(blob):
 pos=32;sections=[];ind=None;sym=None
 for _ in range(struct.unpack_from('<I',blob,16)[0]):
  cmd,n=struct.unpack_from('<II',blob,pos)
  if cmd==2:sym=struct.unpack_from('<IIII',blob,pos+8)
  if cmd==11:ind=struct.unpack_from('<II',blob,pos+56)
  if cmd==25:
   for j in range(struct.unpack_from('<I',blob,pos+64)[0]):
    at=pos+72+j*80;va,size=struct.unpack_from('<QQ',blob,at+32);flags,ri,stride=struct.unpack_from('<III',blob,at+64)
    if flags&255==8:sections.append((va,size,ri,stride))
  pos+=n
 result={}
 if ind and sym:
  so,count,st,sz=sym
  for va,size,ri,stride in sections:
   for j in range(size//stride):
    idx=struct.unpack_from('<I',blob,ind[0]+4*(ri+j))[0]
    if idx&0xc0000000:continue
    si=struct.unpack_from('<I',blob,so+16*idx)[0];name=blob[st+si:blob.index(b'\0',st+si)].decode();result[va+j*stride]=name
 return result

engines=[];diagnostics=[]
for opt in (0,2,3):
 objects=[]
 commands=[]
 for name in sources:
  obj=OUT/(name+f'.O{opt}.o');objects.append(str(obj));commands.append(['clang-18','-target','arm64-apple-ios17.0',f'-O{opt}','-ffreestanding','-fno-builtin','-fno-stack-protector','-Wall','-Wextra','-Werror','-c',str(OUT/name),'-o',str(obj)])
 lib=OUT/f'O{opt}.dylib';commands.append(['ld64.lld-18','-arch','arm64','-platform_version','ios','17.0','17.0','-dylib','-undefined','dynamic_lookup',*objects,'-o',str(lib)])
 for argv in commands:
  r=subprocess.run(argv,text=True,capture_output=True);diagnostics.append({'argv':argv,'returncode':r.returncode,'stderr':r.stderr});(OUT/'compile.json').write_text(json.dumps(diagnostics,indent=2));assert r.returncode==0,r.stderr
 raw=lib.read_bytes();u,syms=engine(raw);im=imports(raw);assert len(im)==1,im;cut=next(iter(im));assert im[cut]=='_mobilelogic_macore_png_write_IDAT_original_3848c',im
 entry=next(v for n,v,undef in syms if n=='_mobilelogic_png_fixed_find_filter' and not undef);engines.append((u,entry,cut,sha(raw)))
ref,_=engine(original);covered=set()
def reference_hook(u,pc,n,_):
 if pc==0x3848c:u.emu_stop();return
 assert 0x3c144<=pc<0x3d488,hex(pc)
 covered.add(pc)
ref.hook_add(UC_HOOK_CODE,reference_hook)
for u,entry,cut,_ in engines:
 def source_hook(machine,pc,n,data):
  if pc==data:machine.emu_stop()
 u.hook_add(UC_HOOK_CODE,source_hook,cut)
rng=random.Random(0x3c144);cases=8192;passes=[0,0,0];failures=[];filters={}
for case in range(cases):
 data=bytearray(rng.randbytes(SIZE));context=BASE+0x100+case%16;info=BASE+0x800+case%16;row=BASE+0x1000+case%16;previous=BASE+0x2000+(case//16)%16;output=BASE+0x3000+(case//256)%16
 depth=(case%255)+1;bpp=(depth+7)//8
 if case%64==0:depth=bpp=0;length=0
 else:length=bpp+[0,1,7,8,15,16,17,23,24,31,32,33,63,64,65,127,128,255,256,511][(case//16)%20] if case%3 else bpp+rng.randrange(513)
 filter_=[8,16,32,64,128][case%5];filters[str(filter_)]=filters.get(str(filter_),0)+1
 for off,p in [(0x218,previous),(0x220,row),(0x228,output)]:struct.pack_into('<Q',data,context-BASE+off,p)
 data[context-BASE+0x25e]=filter_;data[info-BASE+0x13]=depth;struct.pack_into('<Q',data,info-BASE+8,length)
 if case%4==0:data[row-BASE+1:row-BASE+1+length]=bytes(length)
 elif case%4==1:data[previous-BASE+1:previous-BASE+1+length]=bytes([255])*length
 data=bytes(data);fpcr=(((case//4)%4)<<22)|(((case//16)%4)<<24);fpsr=(case*0x01010101)&0xf800009f
 def initialize(u):
  u.mem_write(BASE,data);u.mem_write(STACK,bytes([0xa5])*0x4000);u.reg_write(UC_ARM64_REG_CPACR_EL1,3<<20)
  for r,v in [(UC_ARM64_REG_SP,STACK+0x3000),(UC_ARM64_REG_X30,STOP),(UC_ARM64_REG_X0,context),(UC_ARM64_REG_X1,info),(UC_ARM64_REG_FPCR,fpcr),(UC_ARM64_REG_FPSR,fpsr)]:u.reg_write(r,v)
 initialize(ref);ref.emu_start(0x3c144,STOP,count=100000);assert ref.reg_read(UC_ARM64_REG_PC)==0x3848c
 wanted=bytes(ref.mem_read(BASE,SIZE));call=tuple(ref.reg_read(r) for r in [UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3]);assert call==(context,row if filter_==8 else output,length+1,0)
 for oi,(u,entry,cut,_) in enumerate(engines):
  initialize(u);u.emu_start(entry,STOP,count=100000)
  actual=tuple(u.reg_read(r) for r in [UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3]);ok=u.reg_read(UC_ARM64_REG_PC)==cut and actual==call and bytes(u.mem_read(BASE,SIZE))==wanted and u.reg_read(UC_ARM64_REG_FPCR)==ref.reg_read(UC_ARM64_REG_FPCR) and u.reg_read(UC_ARM64_REG_FPSR)==ref.reg_read(UC_ARM64_REG_FPSR)
  passes[oi]+=int(ok)
  if not ok and len(failures)<16:failures.append({'case':case,'filter':filter_,'optimization':[0,2,3][oi],'memory_equal':bytes(u.mem_read(BASE,SIZE))==wanted,'args_equal':actual==call,'pc':hex(u.reg_read(UC_ARM64_REG_PC))})
report={'image_sha256':sha(original),'original_entry':'0x3c144','native_dependency_cut':'0x3848c','call_site':'0x3cdfc','cases':cases,'comparisons':cases*3,'passes_O0_O2_O3':passes,'mismatches':cases*3-sum(passes),'failures':failures,'filters':filters,'original_instruction_count':len(covered),'original_instruction_locations':list(map(hex,sorted(covered))),'source_sha256':source_hashes,'module_sha256':[x[3] for x in engines],'actual_original_entry_to_first_output_call':True,'dependency_executed':False,'whole_function_verified':False,'full_application_build':False,'limits':['Uninterrupted original entry/prologue/fixed-filter dispatch/transform execution through exact first real output call; no fake callees or resumed successful callbacks.', 'Candidate uses real unresolved external declaration for native MACore 0x3848c. Dynamic-lookup test modules are not closed production builds.', 'Only exact single filter masks 8/16/32/64/128, valid ordinary disjoint buffers, depths 1..255 plus zero-depth empty rows, finite lengths <=544 and 16 alignment offsets. Multimask selection/scoring, output compression, row swapping, flush/callback paths, faults/concurrency remain unresolved.', 'All modeled public memory and real output-call x0..x3 compared; private compiler stack layout and live intra-function callee-saved state are not treated as a return ABI. FPCR/FPSR checked.']}
(OUT/'verification.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2));assert report['mismatches']==0
