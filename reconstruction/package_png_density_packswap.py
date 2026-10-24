"""Reconcile immutable suites without rerunning them; clean-build isolated source."""
import hashlib,json,pathlib,shutil,subprocess
from stage_batch_worker import macho,write
P=pathlib.Path;sha=lambda b:hashlib.sha256(b).hexdigest()
out=P('png-density-source-package');out.mkdir(exist_ok=True)
source=P('reconstruction/macore_png_density_packswap.c');expected='5be9c9b7abd800f8b16a59d6cd097a46d5b9afbdb17130466b1ed4a74d59a1bf';assert sha(source.read_bytes())==expected
inputs=[(x['lane'],P('parents')/x['lane']/('png-density-'+x['lane']),x['artifact_id'],x['zip_sha256']) for x in json.loads(P('reconstruction/PNG_DENSITY_PARENT_INPUTS.json').read_text())]
rows=[];evidence=[]
for kind,path,artifact,digest in inputs:
 report=json.loads((path/('INTERMEDIATE.json' if kind in ('prefix','middle') else 'REPORT.json')).read_text());assert not report['failures']
 assert sha((path/source.name).read_bytes())==expected
 for r in report['functions']:
  assert r['mismatches']==0 and r['all_original_instructions_exercised'] and r['passes']==[r['cases']]*3 and r['complete_function_bounded_test']
  rows.append(dict(r,artifact_id=artifact,evidence_group=kind))
 evidence.append({'kind':kind,'artifact_id':artifact,'artifact_zip_sha256':digest,'functions':len(report['functions']),'comparisons':sum(r['comparisons'] for r in report['functions']),'report_sha256':sha((path/('INTERMEDIATE.json' if kind in ('prefix','middle') else 'REPORT.json')).read_bytes())})
 shutil.copytree(path,out/'evidence'/kind,dirs_exist_ok=True)
assert len(rows)==5 and sum(r['original_bytes'] for r in rows)==708 and sum(r['comparisons'] for r in rows)==245760
keys={(r['image_sha256'],int(r['entry'],0)) for r in rows};assert len(keys)==5
old=json.loads(P('reconstruction/DEPENDENCY_CLOSURE_CHECKPOINT.json').read_text());accepted=old['accepted_function_keys'];assert not keys & {(r['image_sha256'],int(r['entry'],0)) for r in accepted}
candidates=json.loads(P('inventory/all-unsolved-dependencies/ACCEPTED_INDEX_GAPS.json').read_text())['compiled_bounded_getter_candidate_keys'];assert not keys & {(a,int(b,0)) for a,b in candidates}
raw=P('prior/dependency-closure-dossier/MACore.original').read_bytes();image=sha(raw);assert image=='88a8d93c6cb4b411648601efdfc5ca2863c3b833339e55e2470369df1d3bc9d5'
_,sections,starts,_=macho(raw)
for r in rows:
 a=int(r['entry'],0);n=r['original_bytes'];assert a in starts and starts[starts.index(a)+1]==a+n
 sec=next(x for x in sections if x[1]<=a and a+n<=x[1]+x[2]);b=raw[sec[3]+a-sec[1]:sec[3]+a-sec[1]+n];assert sha(b)==r['original_function_sha256']
shutil.copy2(source,out/source.name);shutil.copy2('reconstruction/verify_png_density_packswap.py',out/'verify_png_density_packswap.py');(out/'reference').mkdir(exist_ok=True);(out/'reference/MACore.original').write_bytes(raw)
make='''CC = clang-18
LD = ld64.lld-18
CFLAGS = -target arm64-apple-ios17.0 -O2 -ffreestanding -fno-builtin -fno-stack-protector -ffp-contract=off -frounding-math
all: png_density_packswap.dylib
png_density_packswap.o: macore_png_density_packswap.c
\t$(CC) $(CFLAGS) -c $< -o $@
png_density_packswap.dylib: png_density_packswap.o
\t$(LD) -arch arm64 -platform_version ios 17.0 17.0 -no_fixup_chains -dylib $< -o $@
clean:
\trm -f png_density_packswap.o png_density_packswap.dylib
.PHONY: all clean
''';(out/'Makefile').write_text(make)
r=subprocess.run(['make','clean','all'],cwd=out,capture_output=True,text=True,timeout=120);write(out/'CLEAN_BUILD.json',{'returncode':r.returncode,'stdout':r.stdout,'stderr':r.stderr});assert r.returncode==0,r.stderr
lib=(out/'png_density_packswap.dylib').read_bytes();r=subprocess.run(['llvm-nm-18','--undefined-only',str(out/'png_density_packswap.dylib')],capture_output=True,text=True,timeout=60);assert r.returncode==0 and not r.stdout.strip(),r.stdout
_,newsections,_,newsymbols=macho(lib)
textsec=next(s for s in newsections if s[0]=='__text');textbytes=lib[textsec[3]:textsec[3]+textsec[2]]
for _,path,_,_ in inputs:
 parent=(path/'O2.dylib').read_bytes();_,parentsections,_,parentsymbols=macho(parent);ps=next(s for s in parentsections if s[0]=='__text');assert parent[ps[3]:ps[3]+ps[2]]==textbytes
 for f in rows:assert newsymbols['_ml_png_'+f['name']]==parentsymbols['_ml_png_'+f['name']]
# Auditable section denominator and accepted interval union. It is not a global software percentage.
metadata=json.loads(P('inventory/all-unsolved-dependencies/ALL_IMAGE_DEPENDENCY_METADATA.json').read_text());assert len(metadata)==59 and len({r['image_sha256'] for r in metadata})==59
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
assert not bad and len(allrows)==85 and union==9348
metric={'date':'2026-10-24','native_images':59,'enumerated_instruction_section_union_bytes':den,'excluded_stub_bytes':excluded,'section_overlap_bytes':overlap,'compiler_starts_static_addresses_not_function_total':compiler,'compiler_starts_outside_selected_sections':outside,'accepted_functions':len(allrows),'accepted_original_byte_union':union,'accepted_intervals_inside_sections':len(allrows),'accepted_interval_overlaps':bad,'scope':'accepted original-byte coverage of enumerated instruction sections','percentage':union/den*100,'limits':['Selected section flags may include padding or unmarked embedded data and may omit code outside flagged sections.','No global software completeness bound follows from this section ratio.','Compiler starts are static candidate addresses, not a proven total implementation count.','Finite tests do not prove all-input semantic equivalence.']};write(out/'SECTION_COVERAGE_AUDIT.json',metric)
write(out/'ACCEPTED_DENSITY_FUNCTIONS.json',rows);write(out/'ALL_ACCEPTED_FUNCTION_KEYS.json',allrows)
write(out/'PACKAGE_REPORT.json',{'status':'clean source module built; bounded parent suites reconciled','complete_functions':5,'original_bytes':708,'parent_comparisons':245760,'mismatches':0,'new_runtime_comparisons_in_package':0,'native_imports':[],'source_sha256':expected,'module_sha256':sha(lib),'text_sha256':sha(textbytes),'clean_module_text_and_function_addresses_identical_to_all_tested_O2_modules':True,'evidence':evidence,'strict_cumulative_functions':85,'strict_cumulative_original_byte_union':9348,'all_functions_combined':False,'all_input_proof':False,'whole_native_image_replacement':False,'payload_assembly':False,'reference_evidence_outside_payload':True})
(out/'README.md').write_text('Five actual complete PNG density and packswap functions; 245760 finite original-versus-compiled comparisons across O0/O2/O3. Clean source module has zero native imports and exactly matches tested O2 text and function addresses. No new package execution or complete native-image replacement is claimed. Source and reference evidence are outside Payload. Original packswap table bytes independently match all256values for each of three depths. Rejected harness-budget artifact remains immutable. Finite tests are not all-input proof.\n')
print(json.dumps({'new_functions':5,'parent_comparisons':245760,'strict':85,'original_bytes':9348,'module_sha256':sha(lib),'scope':metric['scope'],'section_percentage':metric['percentage']}))
