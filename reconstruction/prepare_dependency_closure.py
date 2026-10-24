"""Original-data dependency closure dossier; no decompiler retry or stub."""
import hashlib,json,pathlib,struct,zipfile
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_ARM
from stage_batch_worker import macho,original_slice,ARCHIVE_SHA,write
out=pathlib.Path('dependency-closure-dossier');out.mkdir(exist_ok=True)
p=pathlib.Path('MobileLogic.zip')
with p.open('rb') as f:assert hashlib.file_digest(f,'sha256').hexdigest()==ARCHIVE_SHA
with zipfile.ZipFile(p) as z:
 raw=z.read('Frameworks/MACore.framework/MACore')
 assert hashlib.sha256(raw).hexdigest()=='88a8d93c6cb4b411648601efdfc5ca2863c3b833339e55e2470369df1d3bc9d5'
 (out/'MACore.original').write_bytes(raw)
 segs,sections,starts,symbols=macho(raw)
 def read(a,n):return original_slice(raw,sections,a,a+n)
 table=list(struct.unpack('<10Q',read(0x15fd60,80)))
 literals={}
 for a in sorted(set(table+[0x12521e,0x1264d8,0x1264e7,0x12de59])):
  try:
   b=read(a,256).split(b'\0')[0];literals[hex(a)]={'hex':b.hex(),'text':b.decode('utf8','replace')}
  except Exception as e:literals[hex(a)]={'error':str(e)}
 write(out/'LITERALS.json',{'table_address':'0x15fd60','table':list(map(hex,table)),'strings':literals,'warning_constant_12bytes':read(0x11be58,12).hex()})
 dis=Cs(CS_ARCH_ARM64,CS_MODE_ARM)
 for a in [0x2dd78,0x38aa4,0x46ffc,0x47204]:
  assert a in starts
  end=starts[starts.index(a)+1];b=read(a,end-a)
  (out/(hex(a)+'.bin')).write_bytes(b)
  write(out/(hex(a)+'.json'),{'entry':hex(a),'end':hex(end),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'assembly':[{'pc':hex(i.address),'mnemonic':i.mnemonic,'op_str':i.op_str} for i in dis.disasm(b,a)]})
 loads=[]
 for path in ['MobileLogic','Frameworks/DequeModule.framework/DequeModule','Frameworks/InternalCollectionsUtilities.framework/InternalCollectionsUtilities','Frameworks/OrderedCollections.framework/OrderedCollections']:
  if path not in z.namelist():continue
  b=z.read(path);row={'path':path,'sha256':hashlib.sha256(b).hexdigest(),'rpaths':[],'dylibs':[],'dylinker':[]};off=32
  for _ in range(struct.unpack_from('<I',b,16)[0]):
   cmd,size=struct.unpack_from('<II',b,off)
   if cmd in [0x8000001c,0xc,0x18|0x80000000,0x1f|0x80000000,0x20,0xd,0xe]:
    so=struct.unpack_from('<I',b,off+8)[0];s=b[off+so:off+size].split(b'\0')[0].decode()
    key='rpaths' if cmd==0x8000001c else 'dylinker' if cmd==0xe else 'dylibs'
    row[key].append({'command':hex(cmd),'name':s})
   off+=size
  loads.append(row)
 write(out/'RUNPATH_FACTS.json',{'archive_sha256':ARCHIVE_SHA,'images':loads,'claim':'Exact original load commands only; actual platform fallback and runtime exports remain unverified.'})
print(json.dumps({'table':list(map(hex,table)),'functions':[hex(a) for a in [0x2dd78,0x38aa4,0x46ffc,0x47204]],'paths':loads},indent=2))
