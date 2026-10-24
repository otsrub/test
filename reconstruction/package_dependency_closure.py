"""Reconcile accepted keys, refine runpaths and clean-build real source subsets.
Successful differential suites are not repeated; immutable reports required.
"""
import gzip,hashlib,json,pathlib,shutil,subprocess
from stage_batch_worker import write
out=pathlib.Path('dependency-source-package');out.mkdir(exist_ok=True)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
reports={}
for name,p in {'mapper':'mapper-parent/dependency-mapper','claim':'claim-parent/dependency-claim','bits':'bits-parent/png-extension-bits','warning':'warning-parent/png-extension-warning'}.items():
 p=pathlib.Path(p);r=json.loads((p/'REPORT.json').read_text());assert r['mismatches']==0;reports[name]=r
 (out/'evidence').mkdir(exist_ok=True);shutil.copy2(p/'REPORT.json',out/'evidence'/f'{name}-REPORT.json')
 source_name={'mapper':'macore_png_zstream_error.c','claim':'macore_png_claim.c','bits':'macore_png_integer_primitives.c','warning':'macore_png_warning.c'}[name]
 assert r['source_sha256']==sha(p/source_name)
src=out/'src';src.mkdir(exist_ok=True);cand=out/'candidates';cand.mkdir(exist_ok=True)
for p in ['mapper-parent/dependency-mapper/macore_png_zstream_error.c','bits-parent/png-extension-bits/macore_png_integer_primitives.c']:shutil.copy2(p,src)
for p in ['claim-parent/dependency-claim/macore_png_claim.c','warning-parent/png-extension-warning/macore_png_warning.c']:shutil.copy2(p,cand)
reference=out/'reference';reference.mkdir(exist_ok=True);shutil.copy2('prior/dependency-closure-dossier/MACore.original',reference)
make='''CC = clang-18
LD = ld64.lld-18
CFLAGS = -target arm64-apple-ios17.0 -O2 -ffreestanding -fno-builtin -fno-stack-protector
all: module.dylib claim-candidate.o warning-candidate.o
mapper.o: src/macore_png_zstream_error.c
	$(CC) $(CFLAGS) -c $< -o $@
bits.o: src/macore_png_integer_primitives.c
	$(CC) $(CFLAGS) -c $< -o $@
module.dylib: mapper.o bits.o
	$(LD) -arch arm64 -platform_version ios 17.0 17.0 -no_fixup_chains -dylib $^ -o $@
claim-candidate.o: candidates/macore_png_claim.c
	$(CC) $(CFLAGS) -DCLAIM_CANDIDATE -c $< -o $@
warning-candidate.o: candidates/macore_png_warning.c candidates/macore_png_claim.c
	$(CC) $(CFLAGS) -DWARNING_CANDIDATE -c $< -o $@
'''
(out/'Makefile').write_text(make)
r=subprocess.run(['make','-C',str(out)],capture_output=True,text=True,timeout=120);write(out/'BUILD.json',{'returncode':r.returncode,'stdout':r.stdout,'stderr':r.stderr});assert not r.returncode,r.stderr
nm=subprocess.run(['llvm-nm-18','--undefined-only',str(out/'module.dylib')],capture_output=True,text=True,timeout=60);assert not nm.returncode and not nm.stdout.strip(),nm.stdout
accepted=[]
def add(image,address,n,origin):accepted.append({'image_sha256':image,'entry':hex(int(address,0)),'original_bytes':n,'evidence':origin,'scope':'Accepted finite original-byte comparisons; not all-input proof.'})
base=pathlib.Path('history/prior-clean-source-checkpoint/prior-exception-checkpoint/prior-boundary-dossiers/prior-twelve-function-checkpoint')
for rel in ['combined-eight-tests/linked-ios-verification.json','combined-new-tests/verification.json']:
 r=json.loads((base/rel).read_text());assert r.get('total_mismatch_count',r.get('mismatches'))==0
 for f in r['functions']:add(f['image_sha256'],f['address'],len(bytes.fromhex(f['original_hex'])),{'artifact_id':11984977224,'path':str((base/rel).relative_to('history'))})
r=json.loads(pathlib.Path('history/new-tests/verification.json').read_text());assert r['mismatches']==0
for f in r['functions']:
 assert f['passed_per_module']==[f['cases_per_module']]*3
 add(f['image_sha256'],f['address'],f['extent_bytes'],{'artifact_id':11984977224,'path':'new-tests/verification.json'})
h=json.loads(pathlib.Path('reconstruction/logic/LOGIC_HELPER_CHECKPOINT.json').read_text());f=h['complete_function_addition'];assert f['mismatches']==0
add(h['original_image_sha256'],f['entry'],f['original_bytes'],{'artifact_id':f['artifact'],'checkpoint':'LOGIC_HELPER_CHECKPOINT.json'})
h=json.loads(pathlib.Path('reconstruction/logic/PARSER_RECOVERY_CHECKPOINT.json').read_text())
for f in h['evidence']:
 if f.get('complete_function_bounded_tests_passed'):
  assert f['mismatches']==0;add(f['image_sha256'],f['entry'],f['original_bytes'],{'artifact_id':f['artifact_id'],'checkpoint':'PARSER_RECOVERY_CHECKPOINT.json'})
assert len(accepted)==17 and sum(f['original_bytes'] for f in accepted)==1860
historical=list(accepted)
h=json.loads(pathlib.Path('reconstruction/logic/SOURCE_CONTINUATION_CHECKPOINT.json').read_text())
for f in h['strict_complete_function_bounded_test_record']['post_checkpoint_additions']:add(f['image_sha256'],f['entry'],f['bytes'],{'artifact_id':f['artifact_id']})
for f in h['phase_and_rejected_evidence']:
 if f.get('complete_function_bounded_tests_passed'):add(f['image_sha256'],f['entry'],f['original_bytes'],{'artifact_id':f['artifact_id']})
keys=lambda rows:{(f['image_sha256'],int(f['entry'],0)) for f in rows}
assert len(accepted)==len(keys(accepted))==34 and sum(f['original_bytes'] for f in accepted)==5648
new=[{'image_sha256':reports['mapper']['image_sha256'],'entry':reports['mapper']['entry'],'original_bytes':reports['mapper']['original_bytes'],'evidence':{'artifact_id':12554210950}}]
new.extend({'image_sha256':reports['bits']['image_sha256'],'entry':f['entry'],'original_bytes':f['original_bytes'],'evidence':{'artifact_id':12553104746}} for f in reports['bits']['functions'])
gaps=json.loads(pathlib.Path('inventory/all-unsolved-dependencies/ACCEPTED_INDEX_GAPS.json').read_text());getter={(a,int(b,0)) for a,b in gaps['compiled_bounded_getter_candidate_keys']}
assert keys(new).isdisjoint(keys(accepted)|getter)
accepted.extend(new);assert len(keys(accepted))==41 and sum(f['original_bytes'] for f in accepted)==5828
write(out/'ACCEPTED_FUNCTION_KEYS.json',{'functions':accepted,'functions_count':41,'original_bytes':5828,'reindexed_historical_functions':17,'reindexed_historical_bytes':1860,'duplicate_keys':0,'getter_candidates_separate':64,'whole_images_rebuilt':0,'all_input_proof':False})
facts=json.loads(pathlib.Path('prior/dependency-closure-dossier/RUNPATH_FACTS.json').read_text());by_path={r['path']:r for r in facts['images']};refined=[]
with gzip.open('inventory/all-unsolved-dependencies/UNRESOLVED_IMPORTS.jsonl.gz','rt') as f:
 for line in f:
  r=json.loads(line)
  if r['binding']!='symbol_unresolved':continue
  assert r['library']=='@rpath/libswiftCore.dylib';image=by_path[r['image_path']];assert image['sha256']==r['image_sha256']
  paths=[x['name']+'/libswiftCore.dylib' for x in image['rpaths'] if not x['name'].startswith('@')]
  assert paths[0]=='/usr/lib/swift/libswiftCore.dylib'
  refined.append({**r,'prior_binding':r['binding'],'binding':'platform_runpath_candidate_identified','expanded_original_runpaths':paths,'export_presence_verified':False,'runtime_contract':'unverified'})
assert len(refined)==795
write(out/'RUNPATH_REFINEMENT.json',{'imports':refined,'declarations':795,'images':3,'library_location_candidate':'/usr/lib/swift/libswiftCore.dylib','original_inventory_unchanged':True,'actual_runtime_load_executed':False,'runtime_exports_verified':False,'basis':'Exact original LC_RPATH plus documented @rpath expansion. Candidate location only, not export/ABI/all-input verification.','primary_documentation':'https://developer.apple.com/library/archive/documentation/DeveloperTools/Conceptual/DynamicLibraries/100-Articles/RunpathDependentLibraries.html'})
shutil.copy2('prior/dependency-closure-dossier/RUNPATH_FACTS.json',out/'ORIGINAL_RUNPATH_FACTS.json')
report={'strict_complete_function_bounded_test_record':{'functions':41,'original_bytes':5828,'historical_keys_now_complete':True,'all_input_proof':False},'new_complete_functions':7,'new_original_bytes':180,'parent_comparisons':sum(r['comparisons'] for r in reports.values()),'parent_mismatches':0,'leaf_subset_clean_build':True,'leaf_module_sha256':sha(out/'module.dylib'),'leaf_subset_functions':7,'leaf_native_imports':0,'candidate_objects_have_real_unresolved_dependencies':True,'combined_leaf_module_runtime_retested':False,'runpath_declarations_refined':795,'runtime_exports_verified':False,'whole_native_images_rebuilt':0,'payload_assembly':False,'source_files':{str(p.relative_to(out)):sha(p) for p in out.rglob('*.c')},'limits':['Separate parent source modules were runtime compared with original bytes. Fresh combined leaf dylib build is not new combined-module runtime evidence.','Claim and warning remain source/call-boundary candidates with actual callbacks/zlib/stdio unresolved.','No recovered source or evidence was placed in Payload.','Static import path classification is separate from real platform implementation and integration verification.']}
write(out/'PACKAGE_REPORT.json',report);print(json.dumps(report,indent=2))
