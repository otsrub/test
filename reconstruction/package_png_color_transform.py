"""Reconcile immutable suites without rerunning them; clean-build isolated source."""
import hashlib,json,pathlib,shutil,subprocess
from stage_batch_worker import macho,write
P=pathlib.Path;sha=lambda b:hashlib.sha256(b).hexdigest()
out=P('png-color-source-package');out.mkdir(exist_ok=True)
source=P('reconstruction/macore_png_color_transform.c');expected='8ec4a7aee5625b1198d3eecad60b80351e889063939a0759da7cf75df62abd6b';assert sha(source.read_bytes())==expected
inputs=[('chromaticity',P('parents/chromaticity/png-color-chromaticity'),12564368122,'341dee301dccda6ad57b1e38c121183ce32eacf0053bc6e412acb9a9192cb663'),('configuration',P('parents/configuration/png-color-configuration'),12564173874,'5b1b20a57433645bc84834d4e489ca34afd9033d035bda1f5c54bfb8bfcc1bca')]
rows=[];evidence=[]
for kind,path,artifact,digest in inputs:
 report=json.loads((path/('INTERMEDIATE.json' if kind in ('prefix','middle') else 'REPORT.json')).read_text());assert not report['failures']
 assert sha((path/source.name).read_bytes())==expected
 for r in report['functions']:
  assert r['mismatches']==0 and r['all_original_instructions_exercised'] and r['passes']==[r['cases']]*3 and r['complete_function_bounded_test']
  rows.append(dict(r,artifact_id=artifact,evidence_group=kind))
 evidence.append({'kind':kind,'artifact_id':artifact,'artifact_zip_sha256':digest,'functions':len(report['functions']),'comparisons':sum(r['comparisons'] for r in report['functions']),'report_sha256':sha((path/('INTERMEDIATE.json' if kind in ('prefix','middle') else 'REPORT.json')).read_bytes())})
 shutil.copytree(path,out/'evidence'/kind,dirs_exist_ok=True)
assert len(rows)==11 and sum(r['original_bytes'] for r in rows)==848 and sum(r['comparisons'] for r in rows)==319488
keys={(r['image_sha256'],int(r['entry'],0)) for r in rows};assert len(keys)==11
old=json.loads(P('reconstruction/DEPENDENCY_CLOSURE_CHECKPOINT.json').read_text());accepted=old['accepted_function_keys'];assert not keys & {(r['image_sha256'],int(r['entry'],0)) for r in accepted}
candidates=json.loads(P('inventory/all-unsolved-dependencies/ACCEPTED_INDEX_GAPS.json').read_text())['compiled_bounded_getter_candidate_keys'];assert not keys & {(a,int(b,0)) for a,b in candidates}
raw=P('prior/dependency-closure-dossier/MACore.original').read_bytes();image=sha(raw);assert image=='88a8d93c6cb4b411648601efdfc5ca2863c3b833339e55e2470369df1d3bc9d5'
_,sections,starts,_=macho(raw)
for r in rows:
 a=int(r['entry'],0);n=r['original_bytes'];assert a in starts and starts[starts.index(a)+1]==a+n
 sec=next(x for x in sections if x[1]<=a and a+n<=x[1]+x[2]);b=raw[sec[3]+a-sec[1]:sec[3]+a-sec[1]+n];assert sha(b)==r['original_function_sha256']
shutil.copy2(source,out/source.name);shutil.copy2('reconstruction/verify_png_color_transform.py',out/'verify_png_color_transform.py');(out/'reference').mkdir(exist_ok=True);(out/'reference/MACore.original').write_bytes(raw)
make='''CC = clang-18
LD = ld64.lld-18
CFLAGS = -target arm64-apple-ios17.0 -O2 -ffreestanding -fno-builtin -fno-stack-protector -ffp-contract=off -frounding-math
all: png_color_transform.dylib
png_color_transform.o: macore_png_color_transform.c
\t$(CC) $(CFLAGS) -c $< -o $@
png_color_transform.dylib: png_color_transform.o
\t$(LD) -arch arm64 -platform_version ios 17.0 17.0 -no_fixup_chains -dylib $< -o $@
clean:
\trm -f png_color_transform.o png_color_transform.dylib
.PHONY: all clean
''';(out/'Makefile').write_text(make)
r=subprocess.run(['make','clean','all'],cwd=out,capture_output=True,text=True,timeout=120);write(out/'CLEAN_BUILD.json',{'returncode':r.returncode,'stdout':r.stdout,'stderr':r.stderr});assert r.returncode==0,r.stderr
lib=(out/'png_color_transform.dylib').read_bytes();r=subprocess.run(['llvm-nm-18','--undefined-only',str(out/'png_color_transform.dylib')],capture_output=True,text=True,timeout=60);assert r.returncode==0 and not r.stdout.strip(),r.stdout
_,newsections,_,newsymbols=macho(lib)
textsec=next(s for s in newsections if s[0]=='__text');textbytes=lib[textsec[3]:textsec[3]+textsec[2]]
for _,path,_,_ in inputs:
 parent=(path/'O2.dylib').read_bytes();_,parentsections,_,parentsymbols=macho(parent);ps=next(s for s in parentsections if s[0]=='__text');assert parent[ps[3]:ps[3]+ps[2]]==textbytes
 for f in rows:assert newsymbols['_ml_png_'+f['name']]==parentsymbols['_ml_png_'+f['name']]
# Filler is buildable as an object with real unresolved native declarations.
cs=P('reconstruction/macore_png_set_filler_candidate.c');shutil.copy2(cs,out/cs.name);shutil.copy2('reconstruction/PNG_FILLER_DEPENDENCIES_20261024.json',out/'PNG_FILLER_DEPENDENCIES_20261024.json')
cmd=['clang-18','-target','arm64-apple-ios17.0','-O2','-ffreestanding','-fno-builtin','-fno-stack-protector','-c',str(cs),'-o',str(out/'filler_candidate.o')];r=subprocess.run(cmd,capture_output=True,text=True,timeout=60);assert r.returncode==0,r.stderr
nm=subprocess.run(['llvm-nm-18','--undefined-only',str(out/'filler_candidate.o')],capture_output=True,text=True,timeout=60);assert nm.returncode==0;undefined={line.split()[-1] for line in nm.stdout.splitlines() if line.strip()};assert undefined=={'_png_warning','_png_error'},undefined
assert starts[starts.index(0x100ad8)+1]==0x100b9c
_,_,_,original_symbols=macho(raw);assert original_symbols['_png_warning']==0x47204 and original_symbols['_png_error']==0x46fcc
read=lambda a,n:next(raw[o+a-v:o+a-v+n] for _,v,s,o,_ in sections if v<=a and a+n<=v+s)
for pc,target in [(0x100b68,0x47204),(0x100b80,0x47204),(0x100b8c,0x46fcc),(0x100b98,0x46fcc)]:
 w=int.from_bytes(read(pc,4),'little');assert w>>26 in (5,37);imm=w&0x3ffffff;imm=imm-(1<<26) if imm&(1<<25) else imm;assert pc+(imm<<2)==target
for a,text in [(0x132149,b'png_set_filler is invalid for low bit depth gray output\0'),(0x132181,b'png_set_filler: inappropriate color type\0')]:assert read(a,len(text))==text
write(out/'FILLER_CANDIDATE_BUILD.json',{'status':'object-only candidate with real unresolved native functions','source_sha256':sha(cs.read_bytes()),'object_sha256':sha((out/'filler_candidate.o').read_bytes()),'undefined_native_symbols':sorted(undefined),'original_native_branch_targets_checked':4,'original_literal_strings_checked':2,'original_function_sha256':sha(read(0x100ad8,196)),'runtime_comparisons':0,'complete_function_accepted':False,'fake_stubs':False})
es=P('reconstruction/macore_png_error_chain_candidates.c');shutil.copy2(es,out/es.name)
cmd=['clang-18','-target','arm64-apple-ios17.0','-O2','-ffreestanding','-fno-builtin','-fno-stack-protector','-c',str(es),'-o',str(out/'error_chain_candidates.o')];r=subprocess.run(cmd,capture_output=True,text=True,timeout=60);assert r.returncode==0,r.stderr
nm=subprocess.run(['llvm-nm-18','--undefined-only',str(out/'error_chain_candidates.o')],capture_output=True,text=True,timeout=60);assert nm.returncode==0;undefined={line.split()[-1] for line in nm.stdout.splitlines() if line.strip()};assert undefined=={'___stderrp','_fprintf','_fputc','_abort'},undefined
for a,text in [(0x126f45,b'libpng error: %s\0'),(0x126f56,b'undefined\0')]:assert read(a,len(text))==text
write(out/'ERROR_CHAIN_CANDIDATE_BUILD.json',{'status':'three object-only source candidates; real external stdio/abort and callbacks unresolved','source_sha256':sha(es.read_bytes()),'object_sha256':sha((out/'error_chain_candidates.o').read_bytes()),'undefined_native_symbols':sorted(undefined),'original_literal_strings_checked':2,'original_functions':[{'entry':hex(a),'bytes':n,'sha256':sha(read(a,n))} for a,n in [(0x46fcc,48),(0x46ffc,88),(0x47054,36)]],'runtime_comparisons':0,'complete_functions_accepted':0,'fake_stubs':False})
# Auditable section denominator and accepted interval union. It is not a global software percentage.
metadata=json.loads(P('inventory/all-unsolved-dependencies/ALL_IMAGE_DEPENDENCY_METADATA.json').read_text());assert len(metadata)==59 and len({r['image_sha256'] for r in metadata})==59
m=next(x for x in metadata if x['image_sha256']==image)
for a,sym in [('0x104be4','_fprintf'),('0x104bf0','_fputc'),('0x104938','_abort')]:
 imp=m['stubs'][a];assert imp['symbol']==sym and m['dependencies'][imp['library_ordinal']-1]['name']=='/usr/lib/libSystem.B.dylib'
imp=m['pointer_imports']['0x15ce18'];assert imp['symbol']=='___stderrp' and m['dependencies'][imp['library_ordinal']-1]['name']=='/usr/lib/libSystem.B.dylib'
sectionmap={};den=excluded=overlap=outside=compiler=0
for m in metadata:
 ranges=[]
 for name,a,n,o,flags in m['sections']:
  if flags&0x80000400:
   if flags&255==8:excluded+=n
   else:ranges.append((a,a+n))
 ranges.sort();last=-1
 for a,b in ranges:overlap+=max(0,min(last,b)-a);den+=max(0,b-max(a,last));last=max(last,b)
 sectionmap[m['image_sha256']]=ranges;compiler+=len(m['compiler_starts']);outside+=sum(not any(a<=s<b for a,b in ranges) for s in m['compiler_starts'])
assert den==93551620 and excluded==446952 and overlap==0 and outside==0
allrows=accepted+rows;union=0;intervals={};bad=[]
for r in allrows:
 a=int(r['entry'],0);b=a+r['original_bytes'];h=r['image_sha256'];assert any(lo<=a and b<=hi for lo,hi in sectionmap[h]),r
 intervals.setdefault(h,[]).append((a,b))
for h,rs in intervals.items():
 last=-1
 for a,b in sorted(rs):
  if a<last:bad.append((h,a,b,last))
  union+=max(0,b-max(last,a));last=max(last,b)
assert not bad and len(allrows)==80 and union==8640
metric={'date':'2026-10-24','native_images':59,'enumerated_instruction_section_union_bytes':den,'excluded_stub_bytes':excluded,'section_overlap_bytes':overlap,'compiler_starts_static_addresses_not_function_total':compiler,'compiler_starts_outside_selected_sections':outside,'accepted_functions':len(allrows),'accepted_original_byte_union':union,'accepted_intervals_inside_sections':len(allrows),'accepted_interval_overlaps':bad,'scope':'accepted original-byte coverage of enumerated instruction sections','percentage':union/den*100,'limits':['Selected section flags may include padding or unmarked embedded data and may omit code outside flagged sections.','No global software completeness bound follows from this section ratio.','Compiler starts are static candidate addresses, not a proven total implementation count.','Finite tests do not prove all-input semantic equivalence.']};write(out/'SECTION_COVERAGE_AUDIT.json',metric)
write(out/'ACCEPTED_COLOR_FUNCTIONS.json',rows);write(out/'ALL_ACCEPTED_FUNCTION_KEYS.json',allrows)
write(out/'PACKAGE_REPORT.json',{'status':'clean source module built; bounded parent suites reconciled','complete_functions':11,'original_bytes':848,'parent_comparisons':319488,'mismatches':0,'new_runtime_comparisons_in_package':0,'native_imports':[],'source_sha256':expected,'module_sha256':sha(lib),'text_sha256':sha(textbytes),'clean_module_text_and_function_addresses_identical_to_all_tested_O2_modules':True,'evidence':evidence,'strict_cumulative_functions':80,'strict_cumulative_original_byte_union':8640,'all_functions_combined':False,'all_input_proof':False,'whole_native_image_replacement':False,'payload_assembly':False,'reference_evidence_outside_payload':True})
(out/'README.md').write_text('11 actual complete PNG chromaticity/configuration functions. 319488 finite original-versus-compiled comparisons across O0/O2/O3 passed. make clean all builds this isolated arm64 iOS source module with zero native imports; its full __text and function addresses match both tested O2 modules. No new execution is claimed for the package. Filler is a separate unresolved source candidate object: real png_warning and png_error declarations, no fake callees and no whole-function runtime acceptance. Other accepted functions remain separate historical modules. No complete native-image or Payload replacement or all-input proof is claimed. Reference and evidence remain outside Payload.\n')
print(json.dumps({'new_functions':11,'parent_comparisons':319488,'strict':80,'original_bytes':8640,'module_sha256':sha(lib),'scope':metric['scope'],'section_percentage':metric['percentage']}))
