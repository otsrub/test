# GUI repair and GetAllEvents continuation — 15 October 2026

No new decompiler attempts or full-image recovery were performed. Original image hashes and previous checkpoints are preserved. The strict verified subset remains fourteen functions / 656 original instruction bytes. Automatic failure records remain twelve (eleven implementations and a thunk), with 72 unresolved compiler-boundary records.

## Corrected source, not just more passing inputs

Overlap testing exposed 2,046 original-vs-candidate mismatches in first ComposeLine at `MAPlugInGUI:0x25210` across O0/O2/O3. The rejected candidate cached the mask byte when the original reloaded it after channel stores. Modes 8 and 14 also required preserving cached source-channel values across output writes. The source now follows the observed load/store sequence. Second ComposeLine at `0x26390` passed all 16,200 overlap inputs without a separate arithmetic repair.

Non-null callback testing exposed 288 O0 mismatches per overload: the rejected candidate used different event objects for the initialization and per-row callback phases, while the original reused one object. The corrected source uses one object in both phases. Optimized builds happened to reuse stack storage before this source fix; that was not sufficient source-level evidence.

The callback tests execute an unchanged original Logic leaf, `Logic:0x587b3c`, rather than a substitute callback. Its bytes were independently checked against the full original Logic image SHA256 `8dc0169c2d2bd0b15a48340a9f1c1508315cd33a2cce3f49704de5ba51734287`, and its extent hash is `4599fa82ca6aa1474ff06e6b8a574b6cbe3888c0299357202a9bd38d9ee5b150`. This position-independent leaf is mapped with an explicit `0x10000000` image load slide to avoid colliding normalized addresses between images. No instruction bytes were changed.

| New check | Inputs | ARM64 O0/O2/O3 comparisons | Mismatches after repair |
|---|---:|---:|---:|
| First ComposeLine overlapping buffers | 19,440 | 58,320 | 0 |
| Second ComposeLine overlapping buffers | 16,200 | 48,600 | 0 |
| Both overloads with original callback | 1,280 | 3,840 | 0 |

All 110,760 new comparisons passed. The repaired source and its dependent overload also passed the prior 128,304 host/ARM64 regression comparisons. Tests compare full modeled data memory, x19–x29/SP, low 64 bits of v8–v15 and FPSR. Callback observations include initialized event fields, context, pointer/index progression and within-sequence event identity. Uninitialized initial event.mode and padding are intentionally excluded.

Access sets are **not identical** in every test: first-overload access-byte sets matched 19,424/19,440 inputs for each optimization; the second matched 12,723 / 12,899 / 13,127. These differences are retained in reports and preclude claims about faulting memory, MMIO, exact accesses, concurrency or unrestricted equivalence. No arbitrary-callback, reentrancy, exception, exact stack-address, callback-pointer mutation or application integration claim is made.

**Scope correction:** the immutable callback report says “index wrapping,” but the test does not exercise 32-bit event-index overflow. It verifies index progression only. The script in this review package corrects that description; the original checkpoint is preserved unchanged.

## Next failed function: CDS1Seq::GetAllEvents

Original `MADSP:0xa946c` has a compiler-delimited extent `[0xa946c,0xa9f80)`, 2,836 bytes. A C pre-allocation phase is recovered and tested, from original `0xa94bc` until the real allocation call at `0xa94fc`. It includes out-of-line scalar and SIMD count loops and clearing the prior-output pointer. It derives the allocation argument from selected step/lane counts and optional property counts, retaining signed-count extension, modulo arithmetic, low-32-bit truncation and the all-ones allocation argument on negative low-word counts.

3,600 inputs at host O0/O2/O3 and compiled iOS ARM64 O0/O2/O3 passed: **21,600 comparisons, zero mismatches**. These exercise 216 original instruction locations, scalar/SIMD transition sizes, signed count edges, overflow, four selections, noncanonical include flags and sixteen alignment offsets. Full modeled data memory and allocation argument are compared. The phase-only ARM64 modules link with zero undefined symbols.

This is not a GetAllEvents replacement. Original free/allocation and `CStepSync::Process` are not executed or replaced. The event-emission loops, floating-point scheduling/DSP semantics, full ABI integration and callers remain unresolved. No new function gap is declared closed.

## Durable checkpoints

- GUI repaired source: commit `82d97f9df999281fbad5b7ba55ceb9a634e92a78`; workflow `38780331470`; artifact `11995486871`, SHA256 `007651b33544e31167fcb4367068cc79abb82fa240abfc5173ab41dcca8c2609`.
- GetAllEvents phase: commit `437fcca96f46ce0ebaa1b443df2d3de2b557fe57`; workflow `38781063249`; artifact `11996186499`, SHA256 `cc1bd2442c37fb98468c017ce47db4b6ab485136e737fde7252d4414c1d1b53e`.
- Each checkpoint carries its immutable predecessor and original hashes. Baseline source, counterexamples and repaired diagnostics are retained.

The remaining original decompiler failures and whole-app link/runtime reconstruction are not solved by these milestones. No modified IPA is produced.
