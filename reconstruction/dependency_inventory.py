"""All-image static dependency inventory. Never equates static binding with runtime closure."""
import argparse
import bisect
import collections
import gzip
import hashlib
import json
import os
import pathlib
import re
import struct
import zipfile
from stage_batch_worker import ARCHIVE_SHA, macho, write


def uleb(raw, cursor, end):
    value = shift = 0
    while cursor < end:
        byte = raw[cursor]; cursor += 1
        value |= (byte & 127) << shift
        if not byte & 128: return value, cursor
        shift += 7
        if shift > 63: raise ValueError('ULEB overflow')
    raise ValueError('Truncated ULEB')


def export_trie(raw, start, length, base):
    exports, stack = {}, [(start, '', frozenset())]
    end = start + length
    while stack:
        cursor, name, visited = stack.pop()
        if cursor in visited: raise ValueError('Export trie cycle')
        assert start <= cursor < end
        visited = visited | {cursor}
        terminal, cursor = uleb(raw, cursor, end)
        children = cursor + terminal
        assert children < end
        if terminal:
            flags, p = uleb(raw, cursor, children)
            if flags & 8:
                ordinal, p = uleb(raw, p, children)
                stop = raw.index(b'\0', p, children)
                exports[name] = {'reexport_ordinal': ordinal,
                                 'reexport_name': raw[p:stop].decode() or name, 'flags': flags}
            else:
                address, p = uleb(raw, p, children)
                exports[name] = {'vmaddr': address if flags & 3 == 2 else base + address,
                                 'flags': flags}
                if flags & 16:
                    resolver, _ = uleb(raw, p, children)
                    exports[name]['resolver_vmaddr'] = base + resolver
        count = raw[children]; p = children + 1
        for _ in range(count):
            stop = raw.index(b'\0', p, end)
            edge = raw[p:stop].decode(); p = stop + 1
            relative, p = uleb(raw, p, end)
            stack.append((start + relative, name + edge, visited))
    return exports


def metadata(raw, path, digest):
    segments, sections, starts, symbols = macho(raw)
    base = next(v for n, v, *_ in segments if n == '__TEXT')
    deps, imports, exports, stubs, pointer_imports, data_in_code, encryption = [], [], {}, {}, {}, [], []
    platform_versions = []
    symtab = indirect = trie = dice = chained = None
    section_bindings = []
    offset, install_name = 32, None
    for _ in range(struct.unpack_from('<I', raw, 16)[0]):
        cmd, size = struct.unpack_from('<II', raw, offset)
        if cmd in (0xc, 0x80000018, 0x8000001f, 0x80000023, 0xd):
            no = struct.unpack_from('<I', raw, offset+8)[0]
            name = raw[offset+no:offset+size].split(b'\0')[0].decode()
            if cmd == 0xd: install_name = name
            else: deps.append({'ordinal': len(deps)+1, 'name': name,
                               'current_version':struct.unpack_from('<I',raw,offset+16)[0],
                               'compatibility_version':struct.unpack_from('<I',raw,offset+20)[0],
                               'kind': 'reexport' if cmd == 0x8000001f else 'weak' if cmd == 0x80000018 else 'upward' if cmd == 0x80000023 else 'load'})
        elif cmd == 2: symtab = struct.unpack_from('<IIII', raw, offset+8)
        elif cmd == 0xb: indirect = struct.unpack_from('<II', raw, offset+56)
        elif cmd in (0x22, 0x80000022):
            a, b = struct.unpack_from('<II', raw, offset+40)
            if b: trie = (a, b)
        elif cmd == 0x80000033: trie = struct.unpack_from('<II', raw, offset+8)
        elif cmd == 0x80000034: chained = struct.unpack_from('<II', raw, offset+8)
        elif cmd == 0x29: dice = struct.unpack_from('<II', raw, offset+8)
        elif cmd in (0x21, 0x2c):
            fo, n, cryptid = struct.unpack_from('<III', raw, offset+8)
            encryption.append({'fileoff': fo, 'bytes': n, 'cryptid': cryptid})
        elif cmd == 0x32:
            platform,minos,sdk = struct.unpack_from('<III',raw,offset+8)
            platform_versions.append({'command':'LC_BUILD_VERSION','platform':platform,'minimum_os_encoded':minos,'sdk_encoded':sdk})
        elif cmd in (0x24,0x25,0x2f,0x30):
            minimum,sdk = struct.unpack_from('<II',raw,offset+8)
            platform_versions.append({'command':hex(cmd),'minimum_os_encoded':minimum,'sdk_encoded':sdk})
        elif cmd == 0x19:
            for i in range(struct.unpack_from('<I', raw, offset+64)[0]):
                p = offset+72+i*80
                va, length = struct.unpack_from('<QQ', raw, p+32)
                flags, first, stride = struct.unpack_from('<III', raw, p+64)
                if flags & 255 in (6, 7, 8, 16):
                    section_bindings.append((va, length, first, stride if flags & 255 == 8 else 8, flags & 255))
        offset += size
    symbol_rows = []
    if symtab:
        so, count, strings, stringsize = symtab
        for i in range(count):
            ix, typ, sect, desc, value = struct.unpack_from('<IBBHQ', raw, so+16*i)
            assert ix < stringsize
            name = raw[strings+ix:raw.index(b'\0', strings+ix)].decode(errors='replace') if ix else ''
            ordinal = (desc >> 8) & 255
            row = {'symbol': name, 'library_ordinal': ordinal, 'weak_reference': bool(desc & 0x40),
                   'vmaddr': value, 'type': typ}
            symbol_rows.append(row)
            if name and typ & 0xe == 0 and typ & 1: imports.append(row)
            if name and typ & 0xe in (2, 0xe) and typ & 1 and not typ & 0x10:
                exports[name] = {'vmaddr': value, 'flags': None, 'source': 'external_symtab_definition'}
    if trie and trie[1]: exports.update(export_trie(raw, *trie, base))
    chained_info = None
    if chained and chained[1]:
        start, length = chained
        version, starts_offset, imports_offset, symbols_offset, number, form, symbol_form = struct.unpack_from('<7I', raw, start)
        assert version == 0 and symbol_form == 0, 'Unsupported chained fixup header/symbol format'
        assert not number or form in (1, 2, 3), 'Unsupported chained import format'
        stride = {1: 4, 2: 8, 3: 16}.get(form,0)
        assert imports_offset + stride * number <= length and symbols_offset <= length
        existing = {(r['symbol'],r['library_ordinal'],0) for r in imports}
        chained_bindings = []
        for i in range(number):
            p = start + imports_offset + stride*i
            bits = struct.unpack_from('<Q' if form == 3 else '<I',raw,p)[0]
            ordinal_bits = 16 if form == 3 else 8
            ordinal = bits & ((1 << ordinal_bits)-1)
            # Apple reserves only the top 15 ordinals for negative special values.
            if ordinal > (1 << ordinal_bits)-16: ordinal -= 1 << ordinal_bits
            ordinal = {-1:255,-2:254,-3:253}.get(ordinal,ordinal)
            name_offset = bits >> (32 if form == 3 else 9)
            addend = struct.unpack_from('<q' if form == 3 else '<i',raw,p+(8 if form == 3 else 4))[0] if form in (2,3) else 0
            p = start + symbols_offset + name_offset
            assert start <= p < start+length
            name = raw[p:raw.index(b'\0',p,start+length)].decode(errors='replace')
            chained_bindings.append({'index':i,'symbol':name,'library_ordinal':ordinal,'addend':addend})
            if (name,ordinal,addend) not in existing:
                imports.append({'symbol':name,'library_ordinal':ordinal,
                                'weak_reference':bool(bits & (1 << ordinal_bits)),
                                'vmaddr':0,'type':None,'source':'chained_fixup_import_table','addend':addend})
                existing.add((name,ordinal,addend))
        chained_info = {'imports':number,'format':form,'symbol_format':symbol_form,
                        'pointer_use_sites':'chained use-site/data-flow recovery remains open',
                        'starts_offset':starts_offset,'import_bindings':chained_bindings}
    if indirect:
        for va, length, first, stride, kind in section_bindings:
            assert stride and length % stride == 0
            for i in range(length//stride):
                assert first+i < indirect[1]
                ix = struct.unpack_from('<I', raw, indirect[0]+4*(first+i))[0]
                if ix & 0xc0000000: continue
                assert ix < len(symbol_rows)
                dest = stubs if kind == 8 else pointer_imports
                dest[hex(va+i*stride)] = symbol_rows[ix]
    if dice:
        assert dice[1] % 8 == 0
        for p in range(dice[0], sum(dice), 8):
            fileoff, length, kind = struct.unpack_from('<IHH', raw, p)
            data_in_code.append({'fileoff': fileoff, 'bytes': length, 'kind': kind})
    return {'path': path, 'image_sha256': digest, 'base': base, 'install_name': install_name,
            'file_type': struct.unpack_from('<I', raw, 12)[0], 'dependencies': deps,
            'imports': imports, 'exports': exports, 'stubs': stubs,
            'pointer_imports': pointer_imports, 'data_in_code': data_in_code, 'encryption': encryption,
            'sections': sections, 'compiler_starts': sorted(set(starts)),
            'defined_symbol_names': {hex(a): n for n, a in symbols.items()},
            'chained_fixups':chained_info,'platform_versions':platform_versions}


def image_targets(dependency, images):
    return [i for i in images if i['install_name'] == dependency]


def exported(image, name, images, visited=()):
    key = (image['image_sha256'], name)
    if key in visited or len(visited) >= 16: return []
    visited = visited + (key,)
    result = image['exports'].get(name)
    if result and 'vmaddr' in result:
        return [{'image_sha256': image['image_sha256'], 'address': hex(result['vmaddr']-image['base']),
                 'vmaddr': hex(result['vmaddr']), 'path': image['path'], 'flags': result['flags']}]
    deps = image['dependencies']
    if result and 'reexport_ordinal' in result:
        ordinal = result['reexport_ordinal']
        deps = [d for d in deps if d['ordinal'] == ordinal]
        name = result['reexport_name']
    else: deps = [d for d in deps if d['kind'] == 'reexport']
    found = []
    for dep in deps:
        for target in image_targets(dep['name'], images):
            found += exported(target, name, images, visited)
    return list({(r['image_sha256'], r['address']): r for r in found}.values())


def resolve_import(image, row, images):
    ordinal = row['library_ordinal']; dep = None; found = []
    if ordinal == 0: found = exported(image, row['symbol'], images)
    elif ordinal == 255:
        for target in images:
            if target['file_type'] == 2: found += exported(target, row['symbol'], images)
    elif ordinal == 254 or (ordinal == 253 and row.get('source') == 'chained_fixup_import_table'):
        return {'binding': 'weak_lookup_unresolved' if ordinal == 253 else 'dynamic_lookup_unresolved', 'library': None, 'targets': [],
                'symbol': row['symbol'], 'runtime_contract': 'unverified'}
    else:
        dep = next((d['name'] for d in image['dependencies'] if d['ordinal'] == ordinal), None)
        if dep:
            for target in image_targets(dep, images): found += exported(target, row['symbol'], images)
    binding = 'main_executable_candidates' if ordinal == 255 and found else 'payload_symbol_resolved' if len(found) == 1 else 'payload_symbol_ambiguous' if len(found) > 1 else 'symbol_unresolved'
    if row.get('addend'):
        found = [dict(r,address=hex(int(r['address'],16)+row['addend']),
                      vmaddr=hex(int(r['vmaddr'],16)+row['addend']),symbol_addend=row['addend']) for r in found]
    if not found and dep and dep.startswith(('/System/Library/', '/usr/lib/')):
        binding = 'platform_external_contract_unverified'
    return {'binding': binding, 'library': dep, 'symbol': row['symbol'], 'targets': found,
            'runtime_contract': 'unverified'}


def accepted_keys(checkpoint, images):
    rows = list(checkpoint['strict_complete_function_bounded_test_record']['post_checkpoint_additions'])
    rows += [r for r in checkpoint.get('phase_and_rejected_evidence', [])
             if r.get('complete_function_bounded_tests_passed') is True]
    keys = set()
    for row in rows:
        digest = row['image_sha256']; address = int(row['entry'], 16)
        image = next(i for i in images if i['image_sha256'] == digest)
        if address >= image['base']: address -= image['base']
        keys.add((digest, hex(address)))
    return keys


def function_address(image, address):
    starts = image['compiler_starts']; index = bisect.bisect_right(starts, address)-1
    if index < 0: return None
    for _,va,n,_,flags in image['sections']:
        if flags & 0x80000400 and flags & 255 != 8 and va <= address < va+n:
            return starts[index] if starts[index] >= va else None
    return None


def scan(args):
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
    root = pathlib.Path(f'dependency-shard-{args.shard}'); root.mkdir(exist_ok=True)
    archive = pathlib.Path('MobileLogic.zip')
    with archive.open('rb') as f: assert hashlib.file_digest(f, 'sha256').hexdigest() == ARCHIVE_SHA
    ledger = json.loads(pathlib.Path('ledger/ALL_IMAGE_RECONSTRUCTION_LEDGER.json').read_text())
    checkpoint = json.loads(pathlib.Path('reconstruction/logic/SOURCE_CONTINUATION_CHECKPOINT.json').read_text())
    images = []
    with zipfile.ZipFile(archive) as z:
        for image in ledger['images']:
            path, digest = image['original_path'], image['original_image_sha256']
            raw = z.read(path); assert hashlib.sha256(raw).hexdigest() == digest
            try: images.append(metadata(raw, path, digest))
            except Exception as exc:
                write(root/'METADATA_FAILURE.json',{'path':path,'image_sha256':digest,'error':str(exc)})
                raise
        assert len(images) == 59 and len({i['image_sha256'] for i in images}) == 59
        accepted = accepted_keys(checkpoint, images)
        candidate_file = pathlib.Path('stage-packages/stage-source-packages/SUMMARY.json')
        candidates = set()
        if candidate_file.exists():
            package = json.loads(candidate_file.read_text())
            assert package['original_functions'] == 64 and package['parent_mismatches'] == 0
            for image in package['images']:
                for row in image['functions']:
                    candidates.add((image['original_image_sha256'],row['address']))
        write(root/'IMAGE_METADATA.json', images)
        write(root/'ACCEPTED_INDEX.json', {'explicit_accepted_keys': sorted(accepted),
              'compiled_bounded_getter_candidate_keys':sorted(candidates),
              'strict_functions_claimed': checkpoint['strict_complete_function_bounded_test_record']['functions_across_checkpoints'],
              'historical_accepted_keys_missing_from_current_index': checkpoint['strict_complete_function_bounded_test_record']['functions_across_checkpoints']-len(accepted),
              'limits': 'Unindexed history is unknown, not automatically source-unrecovered. Bounded body evidence does not verify every incoming caller contract.'})
        selected = [i for n,i in enumerate(sorted(images,key=lambda r:r['path'])) if n % 4 == args.shard]
        summaries, instructions, edge_count = [], 0, 0
        dis = Cs(CS_ARCH_ARM64, CS_MODE_ARM); dis.skipdata = True
        with gzip.open(root/'CALL_EDGES.jsonl.gz','wt') as stream:
            def emit(row):
                nonlocal edge_count
                edge_count += 1
                if edge_count > 2_000_000: raise ValueError('Two-million edge shard budget exceeded')
                stream.write(json.dumps(row,separators=(',',':'))+'\n')
            for image in selected:
                raw = z.read(image['path']); count = collections.Counter(); issues = []
                start_set = set(image['compiler_starts'])
                code_ranges = [(va,va+n) for _,va,n,_,flags in image['sections'] if flags & 0x80000400]
                binding_cache = {}
                imports = [dict(row, **resolve_import(image,row,images)) for row in image['imports']]
                write(root/'imports'/f"{image['image_sha256']}.json", {'path':image['path'],'image_sha256':image['image_sha256'],'imports':imports})
                encrypted = any(x['cryptid'] for x in image['encryption'])
                try:
                    if encrypted: raise ValueError('Encrypted image: plaintext call graph unavailable')
                    for name, va, length, fo, flags in image['sections']:
                        if not flags & 0x80000400 or flags & 255 == 8: continue
                        # Do not decode LC_DATA_IN_CODE entries as instructions.
                        spans, cursor = [], fo
                        for item in sorted(image['data_in_code'],key=lambda r:r['fileoff']):
                            a,b = max(fo,item['fileoff']), min(fo+length,item['fileoff']+item['bytes'])
                            if a >= b: continue
                            if cursor < a: spans.append((cursor,a))
                            cursor = max(cursor,b); count['declared_data_bytes_excluded'] += b-a
                        if cursor < fo+length: spans.append((cursor,fo+length))
                        for a,b in spans:
                            gap = (-(va+a-fo)) % 4
                            count['alignment_padding_bytes_excluded'] += min(gap,b-a)
                            a += gap
                            if a >= b: continue
                            for pc,size,mnemonic,operands in dis.disasm_lite(raw[a:b],va+a-fo):
                                instructions += 1
                                if instructions > 25_000_000: raise ValueError('25-million decoded-item shard budget exceeded')
                                if mnemonic == '.byte':
                                    count['undecoded_bytes'] += size
                                    emit({'image_sha256':image['image_sha256'],'image_path':image['path'],
                                          'pc':hex(pc-image['base']),'kind':'undecoded_bytes',
                                          'bytes':size,'binding':'decode_unresolved',
                                          'integration_status':'unverified'})
                                    continue
                                count['decoded_instructions'] += 1
                                kind = None; target = None
                                if mnemonic == 'bl': kind='direct_call'; target=int(operands.lstrip('#'),0)
                                elif mnemonic in ('blr','blraa','blrab','blraaz','blrabz'): kind='indirect_call'
                                elif mnemonic in ('br','braa','brab','braaz','brabz'): kind='indirect_branch_or_tail'
                                elif mnemonic in ('svc','hvc','smc','brk','hlt','udf'): kind='runtime_exception_or_trap'
                                elif mnemonic == 'b': kind='direct_branch_or_tail'; target=int(operands.lstrip('#'),0)
                                elif mnemonic.startswith('b.') or mnemonic in ('cbz','cbnz','tbz','tbnz'):
                                    kind='cross_boundary_conditional'; target=int(operands.rsplit('#',1)[1],0)
                                if kind is None: continue
                                caller = function_address(image,pc)
                                if kind in ('direct_branch_or_tail','cross_boundary_conditional') and target is not None:
                                    if function_address(image,target) == caller: continue
                                row={'image_sha256':image['image_sha256'],'image_path':image['path'],
                                     'pc':hex(pc-image['base']),'caller':hex(caller-image['base']) if caller is not None else None,
                                     'kind':kind,'operands':operands,'integration_status':'unverified'}
                                if target is None: row['binding']='runtime_trap_contract_unverified' if kind=='runtime_exception_or_trap' else 'runtime_target_unresolved'
                                elif hex(target) in image['stubs']:
                                    stub = image['stubs'][hex(target)]
                                    key = (stub['symbol'],stub['library_ordinal'])
                                    if key not in binding_cache: binding_cache[key] = resolve_import(image,stub,images)
                                    row.update(binding_cache[key])
                                else:
                                    native = any(lo <= target < hi for lo,hi in code_ranges)
                                    row['binding']='native_target' if native else 'target_outside_image_code_unresolved'
                                    row['targets']=[{'image_sha256':image['image_sha256'],'address':hex(target-image['base']),
                                                     'compiler_function_entry':target in start_set}] if native else []
                                for target_row in row.get('targets',[]):
                                    key=(target_row['image_sha256'],target_row['address'])
                                    target_row['source_body_status']='accepted_bounded_body' if key in accepted else 'compiled_bounded_getter_candidate' if key in candidates else 'not_in_explicit_accepted_index'
                                count[row['binding']] += 1; count[kind] += 1; emit(row)
                except Exception as exc: issues.append(str(exc))
                summaries.append({'path':image['path'],'image_sha256':image['image_sha256'],
                                  'counts':dict(count),'issues':issues,'complete_within_static_scope':not issues})
                write(root/'PROGRESS.json',summaries)
    summary={'shard':args.shard,'shards':4,'original_archive_sha256':ARCHIVE_SHA,
             'repository_commit':os.environ.get('GITHUB_SHA'),'run_id':os.environ.get('GITHUB_RUN_ID'),
             'selected_images':len(selected),'image_reports':summaries,'decoded_items':instructions,
             'dependency_edges':edge_count,'complete_within_static_scope':all(not x['issues'] for x in summaries),
             'limits':['Direct branches across compiler boundaries are candidates, not proven calls.',
                       'Indirect dispatch/closures/reflection/dlsym may introduce additional runtime dependencies.',
                       'Global/data import names are preserved; pointer-use/data-flow recovery remains open.',
                       'Static symbol binding and accepted bounded source bodies do not prove caller/runtime closure.',
                       'No function recovery, no decompiler-profile retries, no new semantic coverage claim.']}
    write(root/'SUMMARY.json',summary);print(json.dumps(summary,indent=2))
    if not summary['complete_within_static_scope']: raise SystemExit('Partial inventory preserved; inspect issues')


def merge():
    roots=sorted(pathlib.Path('shards').glob('rea-dependency-shard-*'))
    assert len(roots)==4
    out=pathlib.Path('all-unsolved-dependencies');out.mkdir(exist_ok=True)
    image_reports=[];totals=collections.Counter();imports=collections.Counter();fan_in=collections.Counter();seen=set();body_status={}
    metadata_rows=None;accepted=None
    with gzip.open(out/'DEPENDENCY_EDGES.jsonl.gz','wt') as edges, gzip.open(out/'UNRESOLVED_IMPORTS.jsonl.gz','wt') as imp:
        for root in roots:
            summary=json.loads((root/'SUMMARY.json').read_text())
            assert summary['complete_within_static_scope'], 'Partial shard cannot masquerade as complete'
            image_reports += summary['image_reports']
            for image in summary['image_reports']: totals.update(image['counts'])
            new_metadata=json.loads((root/'IMAGE_METADATA.json').read_text())
            new_accepted=json.loads((root/'ACCEPTED_INDEX.json').read_text())
            if metadata_rows is not None: assert new_metadata == metadata_rows
            if accepted is not None: assert new_accepted == accepted
            metadata_rows=new_metadata;accepted=new_accepted
            for p in sorted((root/'imports').glob('*.json')):
                r=json.loads(p.read_text())
                for row in r['imports']:
                    imports[row['binding']]+=1
                    imp.write(json.dumps({'image_sha256':r['image_sha256'],'image_path':r['path'],**row},separators=(',',':'))+'\n')
            with gzip.open(root/'CALL_EDGES.jsonl.gz','rt') as stream:
                for line in stream:
                    row=json.loads(line);key=(row['image_sha256'],row['pc'],row['kind'])
                    assert key not in seen;seen.add(key)
                    for target in row.get('targets',[]):
                        if target['source_body_status']!='accepted_bounded_body':
                            fan_in[(target['image_sha256'],target['address'])]+=1
                            body_status[(target['image_sha256'],target['address'])]=target['source_body_status']
                    edges.write(line)
    assert len(image_reports)==59 and len({r['image_sha256'] for r in image_reports})==59
    bysha={r['image_sha256']:r for r in metadata_rows}
    priorities=[{'image_sha256':s,'address':a,'image_path':bysha[s]['path'],'incoming_static_edges':n,
                 'source_body_status':body_status[(s,a)],
                 'required_action':'reconcile_and_integrate_existing_tested_source' if body_status[(s,a)]=='compiled_bounded_getter_candidate' else 'recover_or_reconcile_missing_source_evidence'}
                for (s,a),n in fan_in.most_common()]
    write(out/'SOURCE_DEPENDENCY_PRIORITY_QUEUE.json',priorities)
    write(out/'ALL_IMAGE_DEPENDENCY_METADATA.json',metadata_rows)
    write(out/'ACCEPTED_INDEX_GAPS.json',accepted)
    write(out/'IMAGE_SCAN_REPORTS.json',image_reports)
    load_graph=[]
    for image in metadata_rows:
        for dependency in image['dependencies']:
            targets=image_targets(dependency['name'],metadata_rows)
            binding='payload_image_identity_resolved' if len(targets)==1 else 'payload_image_ambiguous' if targets else 'platform_dependency_contract_unverified' if dependency['name'].startswith(('/System/Library/','/usr/lib/')) else 'load_identity_unresolved'
            load_graph.append({'image_sha256':image['image_sha256'],'image_path':image['path'],**dependency,
                               'binding':binding,'targets':[r['image_sha256'] for r in targets],
                               'runtime_load_contract':'unverified'})
    write(out/'IMAGE_LOAD_GRAPH.json',load_graph)
    result={'images_scanned':59,'static_edges':len(seen),'counts':dict(totals),'import_bindings':dict(imports),
            'repository_commit':os.environ.get('GITHUB_SHA'),'run_id':os.environ.get('GITHUB_RUN_ID'),
            'load_dependencies':len(load_graph),'load_binding_counts':dict(collections.Counter(r['binding'] for r in load_graph)),
            'targets_not_in_explicit_accepted_index':len(priorities),'all_runtime_dependencies_known':False,
            'all_dependencies_solved':False,'whole_images_rebuilt':0,
            'limits':['All 59 image identities and instruction sections scanned within documented budgets.',
                      'Runtime targets, resource-name construction, reflection and external implementation behavior remain open.',
                      'Unknown history keys are kept distinct from definitely unrecovered source.',
                      'Native target resolution is static evidence, never all-input equivalence.']}
    write(out/'SUMMARY.json',result)
    (out/'README.md').write_text('# Unresolved MobileLogic dependency inventory\n\n'
        'All 59 original native images are represented. This is a static inventory; runtime closure remains open.\n\n'
        '* `DEPENDENCY_EDGES.jsonl.gz`: every observed call, indirect dispatch and compiler-boundary-crossing branch.\n'
        '* `UNRESOLVED_IMPORTS.jsonl.gz`: all undefined symbol imports, exact library ordinals and binding classification.\n'
        '* `SOURCE_DEPENDENCY_PRIORITY_QUEUE.json`: unique targets outside the explicit accepted source-key index, ranked by callers.\n'
        '* `ALL_IMAGE_DEPENDENCY_METADATA.json`: load dependencies, exports, stubs, GOT/lazy-pointer imports and original identities.\n'
        '* `ACCEPTED_INDEX_GAPS.json`: missing historical source keys; unknown does not mean unrecovered.\n'
        '* `IMAGE_SCAN_REPORTS.json`: decode coverage and issues for every image.\n\n'
        'No stubs were substituted and no decompiler recovery was rerun. Platform imports require ABI/runtime-contract verification; their source is outside the payload.\n')
    print(json.dumps(result,indent=2))


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--shard',type=int,choices=range(4));parser.add_argument('--merge',action='store_true')
    args=parser.parse_args()
    if args.merge: merge()
    else:
        assert args.shard is not None
        scan(args)
