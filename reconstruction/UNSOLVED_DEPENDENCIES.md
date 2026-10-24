# All-image unresolved dependency inventory

All 59 original native images were scanned in four bounded jobs. The complete evidence is artifact **12541404276**, `rea-all-unsolved-dependencies`, from [run 40047056048](https://github.com/otsrub/test/actions/runs/40047056048), commit `df42e45a446a840e4a928efdc7a5c9a14151d251`.

ZIP SHA256: `78dfc43ebb80e866715d6a413278e27a23659435dc02953cf67467d8b3317727`.

| Requirement | Current evidence |
|---|---:|
| Native image identities scanned | 59 / 59 |
| Static dependency edges | 3,114,769 |
| Indirect call/branch sites with unresolved runtime targets | 392,472 |
| Unresolved symbol import declarations | 795 |
| Weak/dynamic lookup declarations | 549 / 7 |
| Platform import declarations needing external contracts | 48,198 |
| Static target keys outside explicit accepted index | 194,790 |
| Undecoded instruction-section bytes | 72 |
| Whole native images rebuilt from source | 0 / 59 |

These are different units and must not be added or converted into decompilation percentages. The 194,790 keys include branch-target candidates and source whose historical acceptance is not indexed; they are not a proven count of unsolved functions.

## Import-resolution diagnosis

All 795 unresolved symbol declarations refer to `@rpath/libswiftCore.dylib`. The three unresolved library loads occur in `DequeModule`, `InternalCollectionsUtilities`, and `OrderedCollections`. This establishes a runpath/runtime identity gap, **not** 795 proven missing exports. Exact symbols, ordinals, import slots and image identities are preserved. Applicable runtime exports and dyld runpath behavior still need verification. Weak lookup, dynamic lookup and computed dispatch remain separate open requirements.

## Source and runtime closure

The historical strict record remains 34 complete functions / 5,648 original bytes with bounded original-byte comparisons, plus 64 separately tracked getter candidates / 512 bytes. Only 17 of the 34 historical function keys are explicit in the current continuation index; 17 require evidence reconciliation. This inventory does not erase historical acceptance or promote candidates.

The priority queue orders static native targets by incoming references. Full edges retain each caller image hash/address, target identity, binding class and unverified integration status. Platform APIs require actual ABI/behavior integration evidence; replacing them with fake stubs would not resolve dependencies. Actual allocator, TLS, callback, ObjC/Swift dispatch, exception, math, resource and dynamic-name behavior remain open where not separately tested.

## Evidence files

- `DEPENDENCY_EDGES.jsonl.gz`: complete static edge records, including indirect/trap/decode gaps.
- `UNRESOLVED_IMPORTS.jsonl.gz`: all import declarations with binding status; filter that status for unresolved entries.
- `ALL_IMAGE_DEPENDENCY_METADATA.json`: exact Mach-O dependency, import/export, indirect-slot and compiler-start metadata.
- `IMAGE_LOAD_GRAPH.json`: all 1,718 load declarations and their identity classification.
- `SOURCE_DEPENDENCY_PRIORITY_QUEUE.json`: prioritized native target candidates.
- `ACCEPTED_INDEX_GAPS.json`: indexed acceptance and separate getter candidates.
- `IMAGE_SCAN_REPORTS.json`, `SUMMARY.json`, `README.md`: checks, scope and limitations.

All four scans and reconciliation succeeded. Runtime targets, reflection and constructed resource names cannot be exhaustively recovered by this static scan. Dependencies are inventoried; they are not all solved. Source/evidence remain outside Payload. No whole-image replacement or reconstructed-Payload claim is made.
