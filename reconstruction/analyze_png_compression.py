"""Bounded original-byte dossier for the real PNG compression dependency."""
import bisect
import hashlib
import json
import pathlib
import struct
import zipfile
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from stage_batch_worker import ARCHIVE_SHA, macho, original_slice, review, write

archive = pathlib.Path('MobileLogic.zip')
with archive.open('rb') as f:
    assert hashlib.file_digest(f, 'sha256').hexdigest() == ARCHIVE_SHA
with zipfile.ZipFile(archive) as z:
    raw = z.read('Frameworks/MACore.framework/MACore')
digest = hashlib.sha256(raw).hexdigest()
assert digest == '88a8d93c6cb4b411648601efdfc5ca2863c3b833339e55e2470369df1d3bc9d5'
_, sections, starts, symbols = macho(raw)
starts = sorted(set(starts))
dis = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
out = pathlib.Path('png-compression-dossier')
out.mkdir(exist_ok=True)
symtab = indirect = None
stubs = []
offset = 32
for _ in range(struct.unpack_from('<I', raw, 16)[0]):
    cmd, size = struct.unpack_from('<II', raw, offset)
    if cmd == 2:
        symtab = struct.unpack_from('<IIII', raw, offset+8)
    elif cmd == 0xb:
        indirect = struct.unpack_from('<II', raw, offset+56)
    elif cmd == 0x19:
        for i in range(struct.unpack_from('<I', raw, offset+64)[0]):
            p = offset + 72 + i*80
            flags, first, stride = struct.unpack_from('<III', raw, p+64)
            if flags & 0xff == 8:
                address, length = struct.unpack_from('<QQ', raw, p+32)
                assert stride and length % stride == 0
                stubs.append((address, length, first, stride))
    offset += size
assert symtab and indirect
so, count, strings, stringsize = symtab
imports = {}
for address, length, first, stride in stubs:
    for i in range(length//stride):
        assert first+i < indirect[1]
        index = struct.unpack_from('<I', raw, indirect[0]+4*(first+i))[0]
        if index & 0xc0000000:
            continue
        assert index < count
        ix = struct.unpack_from('<I', raw, so+16*index)[0]
        assert ix < stringsize
        name = raw[strings+ix:raw.index(b'\0', strings+ix)].decode(errors='replace')
        imports[address+i*stride] = name
by_address = {}
for name, address in symbols.items():
    by_address.setdefault(address, []).append(name)

def dossier(address, label):
    row = {'image_sha256': digest, 'address': hex(address), 'name': label,
           'origin': 'direct original dependency of composed png_write_finish_row',
           'flags': ['manual_dependency_source_recovery_required']}
    result = review(raw, row, sections, starts, dis)
    assert result['boundary_confirmed'] and result['full_decode']
    for edge in result['control_flow']:
        if edge['kind'] in ('bl', 'b') and edge['operands'].startswith('#'):
            target = int(edge['operands'][1:], 0)
            edge['target'] = hex(target)
            edge['exact_original_import'] = imports.get(target)
            edge['defined_symbols'] = by_address.get(target, [])
            edge['compiler_function_entry'] = target in starts
    end = int(result['end_exclusive'], 16)
    (out / (hex(address) + '-original-function.bin')).write_bytes(
        original_slice(raw, sections, address, end))
    write(out / (hex(address) + '-DOSSIER.json'), result)
    return result

primary = dossier(0x3848c, '_png_compress_IDAT')
callees = sorted({int(e['target'], 16) for e in primary['control_flow']
                  if e['kind'] == 'bl' and e.get('compiler_function_entry')})
details = []
for address in callees[:8]:
    i = bisect.bisect_left(starts, address)
    if i+1 < len(starts) and starts[i+1]-address <= 65536:
        details.append(dossier(address, ','.join(by_address.get(address, [])) or 'native callee'))
summary = {'kind': 'Original compression dependency boundary/call dossier; source remains open',
           'image_sha256': digest, 'entry': primary['address'],
           'end_exclusive': primary['end_exclusive'], 'original_bytes': primary['original_bytes'],
           'original_function_sha256': primary['original_function_sha256'],
           'native_callee_dossiers': len(details), 'native_callee_limit': 8,
           'native_callees_beyond_budget': max(0, len(callees)-8),
           'resolved_calls': primary['control_flow'],
           'rea_decompiler_retries': 0, 'source_verified': False,
           'whole_function_runtime_executed': False, 'whole_images_rebuilt': 0,
           'limits': ['Calls resolved from exact original symbol/indirect-symbol tables.',
                      'Compiler-adjacent boundaries require source/control-flow review.',
                      'No stubs, no full-image recovery, no accepted coverage increment.']}
write(out / 'SUMMARY.json', summary)
print(json.dumps(summary, indent=2))
