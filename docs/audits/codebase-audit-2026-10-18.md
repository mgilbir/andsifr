# Codebase Audit — andsifr (wazero fork) — 2026-10-18

**Target.** `main` @ `1793eb74` (Merge PR #17). Whole tree: root API, `api/`, `sys/`, `experimental/**`,
`cmd/wazero`, `imports/**`, every `internal/**` package (decoder/validator, store/runtime object model,
interpreter, wazevo frontend/SSA/regalloc/backend, amd64 + arm64 ISAs incl. encoders, WASI/sysfs/fd
tables/sockets, file cache, platform, DWARF), docs, examples, Makefile, CI.

**ID scheme.** IDs in this file (`C1`…`C81`) are scoped to this report and are in severity order. Findings
from earlier audits are always written with their file prefix — `[0705-C27]` (= `codebase-audit-2026-07-05.md`
C27), `[0706-U23]` (= `codebase-audit-2026-07-06.md` U23) — so a fixing agent never confuses the series.
Their current status is in §3.0.

**Provenance.** **FORK** = authored by the fork maintainer (Miguel Eduardo Gil Biraud); **UPSTREAM** =
everything else (incl. recent upstream proposal merges the fork carries). *FORK-amplified* = upstream code
whose reach or blast radius a fork change materially increased. Two provenance corrections to earlier reports:
[0705-C25] and [0705-C27] are **UPSTREAM** (`92b738b2` Vacchi; `4e6bf9b1` Cruces), and [0706-U3] is
**UPSTREAM** (`772f1240` Stewart).

**Verification legend.** Every finding is CONFIRMED or PLAUSIBLE. CONFIRMED findings say *how*:
**(lead-repro)** reproduced by the lead auditor through the public API on this machine (linux/amd64,
go1.27.2); **(repro)** reproduced by a subsystem reviewer with a runnable test, then the cited lines re-read by
the lead; **(traced)** the exact code path was read and quoted, not executed. Arm64 findings could not be
executed (no arm64 host/qemu) and are traced + disassembled. Reviewer line citations were re-derived by the
lead for every Critical/High finding (one reviewer's `binary/table.go` / `binary/code.go` numbers were wrong
and are corrected here).

**Method.** Ten parallel subsystem reviews (plus an encoder follow-up) read every non-test source file in
their area in full, re-checked every prior finding, and tried to disprove their own findings; the lead
then independently reproduced or re-traced every Critical/High headline before accepting it. Baseline:
`go build ./...` clean; `go vet ./...` reports asm arg-name mismatches (C78) and io-interface name collisions
(by design, not reported); `go test ./...` **fails** on go1.27.2 (C18). The amd64 encoder was swept against
`objdump` over 359,850 generated instructions with zero defects (a planted bug produced 14,958 failures, so
the sweep is not decorative).

---

## 1. Summary table

| ID | Sev | Prov | Area | One-line issue | Location | Status |
|----|-----|------|------|----------------|----------|--------|
| C1 | **Critical** | UPSTREAM, FORK-amplified | amd64 codegen | `UExtend(const)` address addend is **sign**-extended (and `SExtend` zero-extended) → constant addresses ≥2³¹ access up to 2 GiB *below* the memory base | `internal/engine/wazevo/backend/isa/amd64/lower_mem.go:167-170` | CONFIRMED (lead-repro: host process crash) |
| C2 | High | UPSTREAM | Validator ↔ engines | Typed `select` ref-type immediate: validator skips `2+len(heaptype)` bytes, both engines skip 2 → engines execute bytes the validator never saw (default features) | `internal/wasm/func_validation.go:2240-2290`; `internal/engine/interpreter/compiler.go:935-937`; `internal/engine/wazevo/frontend/lower.go:1122-1125` | CONFIRMED (lead-repro) |
| C3 | High | UPSTREAM | Decoder | Attacker counts size allocations before checking remaining bytes: a 30-byte module makes `CompileModule` die with uncatchable `fatal error: out of memory` (34 GB locals) | `internal/wasm/binary/code.go:67,77`; `section.go:100-283` | CONFIRMED (lead-repro) |
| C4 | High | UPSTREAM | WASI / read-only mounts | `path_open(O_TRUNC|O_CREAT, rights=FD_READ)` truncates/creates files on a **read-only** mount (`WithReadOnlyDirMount`, CLI `--mount=…:ro`) | `internal/sysfs/readfs.go:14-24`; `imports/wasi_snapshot_preview1/fs.go:1726-1768` | CONFIRMED (lead-repro) |
| C5 | High | UPSTREAM, fork-adjacent | Imports | `ImportResolver` returning another Runtime's module: type IDs from different stores compared as ints → mismatched signatures linked → native stack confusion / guest-chosen PC | `internal/wasm/store.go:509-512` | CONFIRMED (lead-repro accept; repro crash) |
| C6 | High | **FORK** (`3bde8fa4`) | wazevo termination | Inline loop-header closed check loads through `entryModuleClosedPtr`, which is only set when the *entry* module was compiled with `ensureTermination` → nil deref, process abort | `internal/engine/wazevo/call_engine.go:281,353-355`; `frontend/lower.go:1379-1385` | CONFIRMED (traced; repro + revert check) |
| C7 | High | **FORK** (`25ea61ec`) | Pre-applied memory | A *refused* pre-applied image is not neutralised: the allocator already returned it, refusal only re-copies the segments over it — the "can never be applied to a different module" promise is false | `internal/wasm/store.go:290-309`; `experimental/memory.go:45-69` | CONFIRMED (traced; repro in all 3 refusal paths) |
| C8 | High | **FORK** (`97db9415`) | Pre-applied memory | The [0705-C2] fix guards only a wasm start *section*; `ModuleConfig` start functions (`_start` default, `_initialize`) still run after the skip → double-applied init | `internal/wasm/store.go:293` vs `runtime.go:366-379` | CONFIRMED (repro) |
| C9 | High | UPSTREAM, FORK-amplified (`630d3404`) | Runtime config | A `CompiledModule` instantiated in a second Runtime (shared cache) ignores that Runtime's `WithMemoryLimitPages`, `WithCoreFeatures`, `WithCloseOnContextDone` | `runtime.go:336-346` | CONFIRMED (repro) |
| C10 | High | UPSTREAM | arm64 codegen | `i32.popcnt` counts 64 bits; `i32.load8_s/16_s` are emitted as 64-bit `ldrsb/ldrsh x` so the upper half is sign-filled → wrong popcount | `backend/isa/arm64/lower_instr.go:1854-1896`; `instr_encoding.go:1279-1284` | CONFIRMED (traced + disassembly; not executed) |
| C11 | High | UPSTREAM, FORK-amplified | Lifecycle / memory | `Close`/`CloseWithExitCode` while guest code is running frees custom-allocator memory immediately → use-after-unmap (SIGSEGV) or cross-instance access with pooled allocators | `internal/wasm/module_instance.go:100-106,147-163` | CONFIRMED (traced; repro) |
| C12 | High | UPSTREAM | Validator (typed refs, gated) | `isRefSubtypeOf` treats every concrete ref as a subtype of every other (`(ref $a) <: (ref $b)`) → `call_ref` under the wrong signature; wazevo has no runtime check | `internal/wasm/module.go:1315-1330` (+`1247-1253`) | CONFIRMED (traced; repro accept) |
| C13 | High | UPSTREAM | Imports (typed refs, gated) | Concrete-ref global/table/tag imports compared by **module-local** type index; plus [0706-U23] rec-group ID collision now reproduced → forged funcref, SIGSEGV | `internal/wasm/store.go:525,578-579,588`; `store.go:672-729` | CONFIRMED (repro) |
| C14 | High | UPSTREAM | Exceptions (gated) | `throw` stores a v128 tag param with a 16-byte store at `i*8` into an `nParams`-element `[]uint64` → Go heap overflow; catch reads it back misaligned | `frontend/lower.go:3575-3584,4833-4856`; `call_engine.go:601-602` | CONFIRMED (traced; repro) |
| C15 | High | UPSTREAM | Exceptions (gated) | `exnref`s held by the guest are raw `uintptr`s; only the latest exception is GC-rooted → `throw_ref` of a saved exnref reads freed Go memory (both engines) | `call_engine.go:603,625,715` | CONFIRMED (repro) |
| C16 | High | UPSTREAM | WASI on Windows | Guest paths containing `\` (`..\..\Windows\win.ini`), drive letters, ADS `:` and device names pass `path.Clean`+`fs.ValidPath` and are joined onto the host root | `imports/wasi_snapshot_preview1/fs.go:1669-1674`; `internal/sysfs/dirfs.go:125-136` | PLAUSIBLE (traced; no Windows host) |
| C17 | High | **FORK** | Process / CI | GitHub Actions is **disabled** on the fork since 2026-07-04; PRs #2–#17 (codegen + security fixes) merged with no CI on any platform; the last two `Test` runs failed/timed out | `.github/workflows/commit.yaml`; repo settings | CONFIRMED (lead: `gh api`) |
| C18 | Med | UPSTREAM code, FORK drift | DX / toolchain | `go test ./...` is red on Go 1.27 (current release): `dwarf.New` error is swallowed so DWARF silently disappears; CI pins 1.25/1.26; `make lint` broken on 1.27 | `internal/wasm/binary/decoder.go:166`; `internal/integration_test/engine/adhoc_test.go:1544-1550`; `Makefile:3` | CONFIRMED (lead-repro) |
| C19 | Med | UPSTREAM | WASI fds | `path_open`/`sock_accept` have no fd cap (the [0706-U5] cap covers only renumber) → guest exhausts the host *process* fd limit; `lazyDir` then panics | `internal/sys/fs.go:290,354`; `internal/descriptor/table.go:57-78`; `internal/sys/lazy.go:124` | CONFIRMED (repro) |
| C20 | Med | UPSTREAM | WASI sockets | `fd_close` on an accepted TCP conn never closes the socket (`close→Shutdown→close` no-op); `SHUT_RD|SHUT_WR` evaluates to `SHUT_WR` | `internal/sysfs/sock.go:161-167`; `sock_supported.go:50-51`; `imports/.../sock.go:176-177` | CONFIRMED (repro) |
| C21 | Med | UPSTREAM | WASI I/O | Multi-iovec `fd_read`/`fd_write`/`sock_*`: partial transfer followed by an error returns `0, errno` → silent data loss (read) / duplication on retry (write) | `imports/.../fs.go:827-833,1306-1312` | CONFIRMED (repro) |
| C22 | Med | UPSTREAM | WASI stdio | Guest can truncate, extend (1 TiB sparse), pwrite and re-time an embedder's stdout/stderr `*os.File` | `internal/sysfs/file.go:13-115` | CONFIRMED (repro) |
| C23 | Med | UPSTREAM | Validator (gated) | Two more unrecovered validator panics from `CompileModule`: defined tag with out-of-range type index (EH); `ref.func` on an index only an elem segment "declares" (typed refs) | `func_validation.go:560,618,1063`; `module.go:321 vs 334`, `488-533` | CONFIRMED (repro) |
| C24 | Med | UPSTREAM | Decoder | Tables of non-reference element type (`i32`, `v128`, any byte) accepted under default features | `internal/wasm/binary/table.go:37-46` | CONFIRMED (lead-repro accept); runtime effect PLAUSIBLE |
| C25 | Med | UPSTREAM | Decoder features | Typed-ref value types (`0x63`/`0x64`) accepted in params, locals, block types, tables without `CoreFeaturesTypedFunctionReferences` — exposes non-null/concrete-ref machinery (and C2) on default runtimes | `binary/value.go:19-29`; `binary/code.go:51-60`; `binary/table.go:37-43` | CONFIRMED (repro) |
| C26 | Med | UPSTREAM | File cache | A corrupt/stale cache entry permanently fails `CompileModule` (never deleted, never recompiled); mmap leaked on deserialize error paths; header offsets/counts outside the CRC | `internal/engine/wazevo/engine.go:152-155`; `engine_cache.go:135-159,249-306` | CONFIRMED (traced; repro) |
| C27 | Med | UPSTREAM | File cache | A failed cache *write* (read-only/full cache dir) fails `CompileModule` although compilation succeeded | `engine_cache.go:44-49,127-132`; `internal/filecache/file_cache.go:46-48` | CONFIRMED (repro) |
| C28 | Med | UPSTREAM | wazevo concurrency | Concurrent `CompileModule` with a listener factory: listener slices assigned after publish, outside the lock; raw `uintptr` into a replaceable slice → SIGSEGV in JIT code | `engine.go:165-188`; `module_engine.go:147-151` | CONFIRMED (repro, 4/4 crash) |
| C29 | Med | UPSTREAM | wazevo concurrency | File-cache hit publishes the compiled module before its entry preambles exist → `ExportedFunction` panics "index out of range" under concurrency | `engine_cache.go:75-82`; `module_engine.go:204` | CONFIRMED (repro, 150/160) |
| C30 | Med | UPSTREAM | Guest → host memory | Unbounded host memory driven by guest: `ref.func` leaks a `functionInstance` per execution; try_table clones the whole stack per entry (bypasses `callStackCeiling`); `table.grow` to ~2³² entries; table importers retained forever | `module_engine.go:322-339`; `call_engine.go:643-664`; `internal/wasm/table.go:303-308`; `store.go:427,551` | CONFIRMED (traced; repro/measured) |
| C31 | Med | **FORK** (`5c0c6e9c`) | SSA load-CSE | Every store scans the whole (only-growing) cache → O(stores × entries) per block; 80k stores: 31.9 s vs 0.23 s without the pass | `internal/engine/wazevo/ssa/pass_load_cse.go:63-67` | CONFIRMED (repro A/B) |
| C32 | Med | UPSTREAM | SSA passes | Redundant-phi elimination needs one fixpoint pass per loop-nesting level; loop-nesting forest is O(blocks × dom-depth); serial compile ignores ctx ([0705-C19]) → minutes per small module | `ssa/pass.go:127-224`; `ssa/pass_cfg.go:155-186`; `builder.go:726` | CONFIRMED (repro, profiled) |
| C33 | Med | UPSTREAM | DWARF | Malformed `.debug_line` (`set_file` past the table, or file 0 in DWARF<5) yields `LineEntry.File == nil`; `dwarf.go` dereferences it inside the trap `recover` path → host crash; debug info is on by default | `internal/wasmdebug/dwarf.go:182,198-201` | PLAUSIBLE (traced into `debug/dwarf` `line.go:467-472`) |
| C34 | Med | UPSTREAM | Listeners | Listener factory identity is not part of the module ID: a second compile with factory L2 runs L1; a factory on the Instantiate/Call ctx is ignored though the doc says it is honored | `internal/wasm/module.go:214-230`; `experimental/listener.go:139-142` | CONFIRMED (repro) |
| C35 | Med | UPSTREAM | Listeners | `MultiFunctionListenerFactory` embeds one `stackIterator` per listener, shared across goroutines/instances → data race, possible index panic | `experimental/listener.go:167-215` | CONFIRMED (repro, `-race`) |
| C36 | Med | UPSTREAM | Lifecycle | Any `InstantiateModule` failure after `toSysContext` leaks the sys context, incl. **bound TCP listeners** (port stays in use) — widens [0705-C8] | `runtime.go:326-353`; `internal/wasm/store.go:374-385` | CONFIRMED (repro) |
| C37 | Med | UPSTREAM | Lifecycle | `CompiledModule.Close` is not idempotent and decrements a refcount shared by every handle of that module ID (across Runtimes with a cache) | `config.go:385-389`; `internal/engine/wazevo/engine.go:663-678` | CONFIRMED (repro) |
| C38 | Med | UPSTREAM | Imports | `ImportResolver` may return a closed module; it is linked and called (and with a custom allocator its memory was already freed) | `internal/wasm/store.go:472-487` | CONFIRMED (repro) |
| C39 | Med | UPSTREAM | Namespace | A failed duplicate-name instantiate deletes the *live* module's name entry, and the start function runs before the uniqueness check | `internal/wasm/store_module_list.go:28-29`; `store.go:375-385` | CONFIRMED (repro) |
| C40 | Med | UPSTREAM | Lifecycle | "Closed, resources not released" state: later `Close`/`Runtime.Close` release nothing; concurrent `FailIfClosed` double-Frees / double-notifies | `internal/wasm/module_instance.go:13-25,100-163` | CONFIRMED (repro) |
| C41 | Med | UPSTREAM | Lifecycle | Use-after-close paths panic on nil maps instead of erroring: `HostModuleBuilder` after `Runtime.Close`, any Runtime after `cache.Close`, compile racing `Close` (escalates [0705-C20]) | `internal/wasm/store.go:765,785`; `cache.go:72-86`; `engine.go:646-653` | CONFIRMED (repro) |
| C42 | Med | UPSTREAM | Interpreter (gated) | `br_on_non_null` drop-range computed after the ref is popped → stranded operand; a live Go heap pointer is returned to the guest | `internal/engine/interpreter/interpreter.go:4657-4665`; `compiler.go:3609-3628` | CONFIRMED (repro) |
| C43 | Med | UPSTREAM | WASI on Windows | Non-blocking `readSocket` leaks an event handle per call; `writeSocket` returns EAGAIN while an overlapped write on a stack `Overlapped` is still in flight | `internal/sysfs/file_windows.go:81,104-112` | CONFIRMED leak (traced); overlapped PLAUSIBLE |
| C44 | Low | UPSTREAM | Interpreter | Remaining unmasked i32 consumers after #2488: `br_if`, `br_table`, `select`, `call_indirect` index, `table.*`, `memory.fill/copy/init` | `interpreter.go:916,923,941,957,1896-1925,1975-2008` | CONFIRMED (repro) |
| C45 | Low | UPSTREAM | Validator / store | Const exprs may `global.get` a **mutable** global; data offsets then differ between engines (wazevo reads a stale `g.Val`) | `internal/wasm/module.go:648-657`; `const_expr.go:281` | CONFIRMED (repro) |
| C46 | Low | UPSTREAM | WASI poll | `poll_oneoff`: `nsubscriptions*48` wraps (index panic → trap); blocking fds polled sequentially; Linux `_poll(-1)` returns immediately; `int32(ms)` truncation | `imports/.../poll.go:64,68,181-210,190`; `internal/sysfs/poll_linux.go:30-35` | CONFIRMED (repro) |
| C47 | Low | UPSTREAM | WASI fds | `fd_renumber(fd, fd)` closes the fd | `internal/sys/fs.go:314-324` | CONFIRMED (repro) |
| C48 | Low | UPSTREAM | WASI FS | `path_symlink` hands guest memory to `FS.Symlink` via `unsafe.String` (no copy) → custom FS validation bypass / TOCTOU | `imports/.../fs.go:1970` | CONFIRMED (repro) |
| C49 | Low | UPSTREAM | WASI FS | `fd_filestat_set_times` on stdio/socket fds: fallback dereferences `f.FS == nil` | `imports/.../fs.go:516-520` | CONFIRMED (repro) |
| C50 | Low | UPSTREAM | WASI sockets | `sock_*` result writes unchecked (`sock_accept` leaks the fd on EFAULT); MSG_PEEK errno; stale "we wait all" comment | `imports/.../sock.go:36-38,96-110,150` | CONFIRMED (traced) |
| C51 | Low | UPSTREAM | WASI preopens | stdio and TCP-listener fds flagged `IsPreopen`: `fd_prestat_get(0)` succeeds with an empty name; dup2 onto stdout impossible | `imports/.../fs.go:1701-1704` | CONFIRMED |
| C52 | Low | UPSTREAM | Termination | Self tail-recursion (`return_call $self`) has no loop header → never interrupted by `WithCloseOnContextDone` on either engine | `frontend/lower.go:1368`; `interpreter/compiler.go:516` | CONFIRMED (repro) |
| C53 | Low | UPSTREAM | Interpreter snapshot | `Snapshot` never records pc; `Restore` forces pc 0 | `interpreter.go:395-421` | PLAUSIBLE |
| C54 | Low | UPSTREAM | Instantiation order | Data applied before elements (spec: elements first); OOB element segment still instantiates | `internal/wasm/store.go:444-448,210-218` | CONFIRMED (repro) |
| C55 | Low | UPSTREAM | Imports | Memory import ignores the `shared` flag mismatch | `internal/wasm/store.go:553-567` | CONFIRMED (repro) |
| C56 | Low | UPSTREAM | Globals | `GlobalInstance.String()` reads stale `g.Val` under wazevo; panics for v128/ref globals | `internal/wasm/store.go:641-652` | CONFIRMED (repro) |
| C57 | Low | UPSTREAM | Host funcs | Reflection-based host funcs quiet f32 signalling NaNs | `internal/wasm/gofunc.go:107,126` | CONFIRMED |
| C58 | Low | UPSTREAM | Lifecycle | `CloseNotifier` runs under `Store.mux` → notifier calling `r.Module` deadlocks `Runtime.Close` | `internal/wasm/store.go:772-779`; `module_instance.go:148-149` | CONFIRMED (repro) |
| C59 | Low | UPSTREAM | Tables | Unlocked append to `involvingModuleInstances` for a re-exported imported table | `internal/wasm/store.go:427` vs `551` | CONFIRMED (`-race`) |
| C60 | Low | UPSTREAM | Builder | One `HostFunc` reused across `Export("a")`, `Export("b")` with `WithGoFunction` → only last name exported; `addFuncs` mutates builder state | `builder.go:245-303`; `internal/wasm/host.go:89-103` | CONFIRMED (repro) |
| C61 | Low | UPSTREAM | Cache | Shared cache's interpreter engine keeps the first Runtime's features (construction-order dependent) | `cache.go:72-75` | CONFIRMED (repro) |
| C62 | Low | UPSTREAM | Host modules | Host modules surface as three different types by path; default `_start` is invoked on host modules | `builder.go:361-371`; `runtime.go:215-225,346-384` | CONFIRMED (repro) |
| C63 | Low | UPSTREAM | API | `InstantiateModule` returns a non-nil closed module together with an error when `_start` fails | `runtime.go:371-382` | CONFIRMED (repro) |
| C64 | Low | UPSTREAM | experimental/sys | `Errno.Unwrap` lacks ERANGE → `errors.Is(ERANGE, syscall.EIO)` true | `experimental/sys/syscall_errno.go` | CONFIRMED (repro) |
| C65 | Low | UPSTREAM | CLI | Guest exit codes ≥256 wrap mod 256 (`proc_exit(256)` → rc 0) | `cmd/wazero/wazero.go:367-372` | CONFIRMED (repro) |
| C66 | Low | UPSTREAM | CLI | `--timeout` deadline starts before compilation, contradicting its comment | `cmd/wazero/wazero.go:294-310` vs `342` | CONFIRMED (repro) |
| C67 | Low | UPSTREAM | Platform | amd64 compiler emits POPCNT but only gates on SSE4.1 | `internal/platform/platform.go:35`; `amd64/machine.go:553-554` | PLAUSIBLE |
| C68 | Low | **FORK** | Docs | `RATIONALE.md` "context cancellation is handled in Go rather than native code" contradicts `3bde8fa4`'s inline native check | `RATIONALE.md:1522-1534` | CONFIRMED |
| C69 | Low | **FORK** (`e8b2bea9`) | Docs | Import-path rename rewrote upstream issue links to non-existent `mgilbir/andsifr/issues/NNNN` | e.g. `internal/emscripten/emscripten.go:165`, `internal/expctxkeys/listener.go:6` | CONFIRMED |
| C70 | Low | **FORK** (`5c0c6e9c`) | SSA load-CSE | The documented `memoryBase + const` decomposition never fires for wasm memory (`UExtend(Iconst)` is not peeled) | `ssa/pass_load_cse.go:31-38,84-104` | CONFIRMED (SSA dump) |
| C71 | Low | **FORK** (unmerged `f8f72c19`) | Docs | Branch `fix/preapplied-any-global-doc` rewrites the [0705-C15] docs on a false premise: data offsets *cannot* reference local globals | `internal/wasm/module.go:570-575` | CONFIRMED (traced; repro) |
| C72 | Low | **FORK** | Tests | `630d3404` re-intern has no test; arm64 [0705-C1] second fix site untested; arm64 golden trap-island tests skipped on amd64 hosts | `runtime.go:340-345`; `arm64/lower_mem.go:406`; `arm64/lower_instr.go:2043` | CONFIRMED (mutation survives) |
| C73 | Low | UPSTREAM | Docs | Further doc examples that don't compile and doc claims that are false (beyond [0705-C23]) | see §3 | CONFIRMED |
| C74 | Low | UPSTREAM | Test helpers / examples | `wazerotest` diverges from real memory semantics; nil-config panics; `table.LookupFunction` type-asserts; three decorative examples | see §3 | CONFIRMED |
| C75 | Low | UPSTREAM | Decoder conformance | Signed LEB over-accept; `ref.null` heap type read as u32; atomic align `>` vs `!=`; `(ref null $t)` tables rejected by `call_indirect`; empty datacount at EOF accepted; data vs elem offset rules drifted | see §3 | CONFIRMED (repro) |
| C76 | Low | UPSTREAM | amd64 codegen | `lowerSelect` calls the getter `icmp.Lowered()` instead of `MarkLowered()` → the Icmp is lowered twice (dead code, double folded load) | `amd64/machine.go:1325` | CONFIRMED (traced) |
| C77 | Low | mixed | Codegen (latent) | Latent hazards not reachable today: arm64 x27 copy-hint (`de68b2c5` + regalloc), arm64 `return_call_indirect` target reg, [0706-U18], encoder RIP-label flag drop, 24-bit try_table IDs, stale dominators | see §3 | CONFIRMED/PLAUSIBLE (latent) |
| C78 | Low | UPSTREAM | Asm | `go vet` asmdecl: arg names in `abi_entry_*.s` don't match Go declarations (`functionExectuable`, `paramResultSlicePtr`) | `amd64/abi_entry_amd64.s:7,10` (+arm64) | CONFIRMED (lead) |
| C79 | Low | UPSTREAM | WASI minor | `osFile.reopen` fd leak; `path_filestat_set_times` no-follow emulation; `ToErrno` collapses EMFILE/ENOSPC/EXDEV to EIO; `ReadFS` ENOSYS vs EROFS; logging decodes rights as Uint16 | see §3 | CONFIRMED (traced) |
| C80 | Low | UPSTREAM | CLI minor | Dev flags hidden in normal builds; no-arg exits 0; `compile` without `--cachedir` persists nothing silently; raw Go usage on bad flag; trace prints `unknown` for v128/funcref | see §3 | CONFIRMED |
| C81 | Low | UPSTREAM | Lifecycle | `CloseNotifier`/`CodeCloser` assigned after the module is registered and visible | `runtime.go:355-363` | PLAUSIBLE |

**Counts:** 81 findings — **Critical 1 · High 16 · Medium 26 · Low 38** (PLAUSIBLE: C16, C33, C53, C67, C81,
parts of C24/C43/C77). Provenance: **FORK 11** (C6, C7, C8, C17, C31, C68–C72, + C9/C11 FORK-amplified),
the rest UPSTREAM. Experimental-flag-gated: C12–C15, C23, C42 (typed function references / exception
handling — memory-unsafe under the flag; see Open question 1).

**The short version.** (1) **C1** is a sandbox escape on stock amd64: any valid module with ≥2 GiB of memory
that touches a constant address ≥2³¹ reads/writes 2 GiB below its own memory; I reproduced it as a host
process crash with a 49-byte module. (2) The untrusted-binary boundary still crashes the host in default
configuration (**C3** fatal OOM, **C2** validated≠executed bytes), and the read-only mount is writable
(**C4**). (3) The fork's own features have structural holes: the pre-applied-image safety checks run *after*
the image is already in memory (**C7**, **C8**), and the inline termination check introduced a crash
(**C6**) on exactly the cross-Runtime path that `630d3404` set out to support — which is itself unsound in
three more ways (**C5**, **C9**, **C37**). (4) None of PRs #2–#17 ran CI (**C17**), and the suite is red on
current Go (**C18**).

---

## 2. System map

### 2.1 Architecture and real execution paths

```
wazero.NewRuntime[WithConfig]            runtime.go:150
  └─ cache? → shared engine (sync.Once, first Runtime's features win — C61)
CompileModule(ctx, bin)                  runtime.go:~230
  ├─ binary.DecodeModule                 internal/wasm/binary/decoder.go
  │    • section decoders size make() from attacker counts      (C3)
  │    • DWARF: d, _ := dwarf.New(...)  — error swallowed         (C18)
  ├─ Module.Validate                     internal/wasm/module.go:~300
  │    • validateFunctions BEFORE validateTagSection/validateTable (C23)
  │    • func_validation.go: per-opcode stack typing; typed-select immediate (C2), ref subtyping (C12)
  │    • NO recover around decode/validate → any panic kills the host
  ├─ AssignModuleID = sha256(bin ‖ flags: listeners?, ensureTermination?)
  └─ engine.CompileModule
       wazevo:  getCompiledModule (memory map, RLock — 755df6b5) → file cache (C26/C27/C29)
                → frontend (wasm→SSA; inline termination check 3bde8fa4 — C6; const-addr bounds elision e24a9ae2)
                → SSA passes (redundant-phi C32, load-CSE 5c0c6e9c C31/C70, layout)
                → backend lower (amd64 C1/C76, arm64 C10) → regalloc → encode → mmap RX
                → listener fields set AFTER publish (C28)
       interp:  compiler.go → IR ops (typed-select skip C2; br_on_non_null C42)
InstantiateModule(ctx, compiled, cfg)    runtime.go:307
  ├─ sockConfig from ctx mutates cfg     ([0705-C10])
  ├─ toSysContext (opens TCP listeners)  → leaked on every later error (C36)
  ├─ typeIDs re-interned iff compiledStore != r.store (630d3404) — but limits/features/termination are NOT (C9)
  └─ Store.Instantiate                   internal/wasm/store.go:~360
       resolveImports  — ImportResolver may return foreign-store (C5) or closed (C38) modules
       buildMemory     — custom allocator returns image (pre-applied) BEFORE the skip decision (C7)
       buildGlobals/Tables, applyData (skip gate: no start SECTION, no global offsets, ID match — C8),
       applyElements (after data — C54), start section,
       registerModule  — name uniqueness checked LAST; failure deletes by name (C39)
  └─ ModuleConfig start functions (_start / _initialize) — after the pre-applied skip (C8)
api.Function.Call → wazevo callWithStack (entryModuleClosedPtr only if entry module ensureTermination — C6)
                  → interpreter callNativeFunc
Close: CloseWithExitCode → ensureResourcesClosed → allocator.Free() immediately (C11)
```

### 2.2 Trust boundaries and the invariants that guard them

| Boundary | Invariant that must hold | Where enforced | Where it breaks |
|---|---|---|---|
| `.wasm` bytes → decoder | every count/index bounded by
---

## 3.0 Fix status (2026-10-18 working session)

Baseline re-checked: `go build ./...` clean, `go vet ./...` only the known asm
arg-name mismatches (C78), `go test ./...` green, `golangci-lint run` 0 issues.

### Fixed this session (verified fixed + regression tests)

| ID | Fix | Test |
|----|-----|------|
| C1 | `lowerAddendFromInstr` (amd64) had `UExtend`/`SExtend` constant handling **swapped**: UExtend (zero-extend) sign-extended, SExtend zero-extended. Restored correct semantics; offsets that no longer fit imm32 take the existing temp-register path in `lowerAddendsToAmode`. | `TestMachine_lowerAddendFromInstr` high-bit cases |
| C2 | Both engines skipped only 2 immediate bytes for typed `select`, while validation skipped `2 + len(heaptype)`. Both now decode the ref-prefix heap type as s33 LEB and skip exactly what validation skipped. | suite (multi-byte heaptype paths); engine-lowering parity |
| C3 | `binary/code.go`: locals `sum` now capped (`maxFunctionLocals = 1_000_000`) before the big `make`; all 9 section decoders bound the vector count by remaining input (`ensureVectorCountFits`) before allocating. The 30-byte-module → fatal OOM repro now returns an error. | `TestDecodeModule_ExcessiveLocalsRejected`, `TestDecodeModule_VectorCountExceedsInputRejected` |
| C4 | `ReadFS.OpenFile` rejects `O_CREAT|O_TRUNC` with `EROFS` before touching the wrapped FS; the readFile wrapper alone could not prevent open-time truncation. The 3 `Test_pathOpen` cases asserting the old (buggy) ENOSYS updated to EROFS. | `TestReadFS_OpenFile_CreatTrunc`, `Test_pathOpen` |
| C5 | `resolveImports` compares `FunctionTypeID`s only when both module instances belong to the same Store (`m.s == importedModule.s`); otherwise structural `EqualsSignature`. Cross-Runtime resolver imports were unsound in **both** directions (false-reject and false-accept — both reproduced). | `TestE2E_cross_runtime_import_signature` (fails both subtests pre-fix) |
| C6 | `callWithStack` now always populates `execCtx.entryModuleClosedPtr`, not only when the *entry* module was compiled with `ensureTermination`. Pre-fix repro confirmed: reverted fix → `runtime.systemstack` fatal. | `TestE2E_cross_runtime_termination_inline_check` |
| C7 | A refused pre-applied image is now neutralised (`clear(mem.Buffer)`) before data segments are copied; previously the image contents survived in all 3 refusal paths. Contract documented in `experimental/memory.go`. | `TestModuleInstance_applyData/pre-applied...` image-content assertions |
| C8 | The pre-applied skip is additionally refused when the embedder's `ModuleConfig` will run a start function that this module exports (`Store.Instantiate` gains `willRunStartFunctions`; computed in `runtime.Instantiate` from `config.startFunctions` ∩ module exports). | `TestModuleInstance_applyData` configStart case |
| C9 | Cross-Runtime instantiation is now refused when the compiling Runtime's `WithMemoryLimitPages`, `WithMemoryCapacityFromMax`, core features or `WithCloseOnContextDone` differ — those are baked into the compiled module and cannot be re-applied. `compiledModule` records them (`runtime.newCompiledModule`); host-module builder fixed to populate `compiledStore` (was nil). | `TestE2E_cross_runtime_config_mismatch` |
| C10 | arm64 `lowerPopcnt`: i32 inputs are zero-extended before the GPR→vec move (i32 upper bits may hold garbage, incl. sign-fill from 64-bit LDRSB/LDRSH forms), and `cnt` uses the 8b arrangement so the stale upper half of the vector lane is never counted (this also fixes latent garbage-counting for i64 popcnt). | arm64 package tests (encoding-level) |
| C11 | `ModuleInstance` gained `BeginExecution`/`EndExecution` (in-flight call counter). `ensureResourcesClosed` defers the allocator `Free` while guest code is executing; the last `EndExecution` performs it. Both engines' entry points (`wazevo.callWithStack`, `interpreter.call`) bracket every guest execution, and a call on an already-closed module is now rejected (restoring upstream wazero behaviour). | `TestE2E_close_during_execution_defers_free` (fails pre-fix); `Test_procExit` updated for the restored entry check |
| C16 | `atPath` (the single guest-path choke point) rejects paths that `fs.ValidPath` cannot judge on Windows: backslashes, `:` (drive letters/ADS) and reserved DOS device names. | `Test_windowsPathNeedsEscape` |
| C18 | `dwarf.New` error no longer silently discarded (degradation documented); the adhoc listener test's minimal DWARF now carries a `.debug_abbrev` section (Go 1.27's `dwarf.New` parses abbrev eagerly) — suite is green on go1.27.2. `Makefile` moves to golangci-lint v2 (v1.64.5 panics on go1.26+ sources) with a v2 `.golangci.yml` preserving the v1-era effective checks; CI matrix bumped to 1.27/1.26. | full `go test ./...`; `make lint`-equivalent 0 issues |

Also fixed en route: `require.equalsPointer` `reflect.Ptr` deprecation, `examples/cli` `runtime.GOROOT` deprecation, errcheck-clean best-effort `Close`/`free.Call` in examples, stale `//nolint:gosimple` → `staticcheck` in regalloc.

### Partially addressed

- **C17 — RESOLVED (2026-10-19)**: Actions were re-enabled via the API
  (`actions/permissions`), a `workflow_dispatch` trigger was added to
  commit.yaml so any ref can be validated on demand, and the full platform
  matrix was run against the fix series (two CI-only test fixes landed on the
  way: the arm64 integer-bit-count goldens for the C10 change and the
  working-directory assumption in TestFSContext_OpenFile_cap). The
  riscv64 scratch-runner jobs were dropped from the matrix: the
  ubuntu-24.04-riscv runner queued indefinitely (maintainer decision).

### Fixed this session, part 2 (C12–C15)

| ID | Fix | Test |
|----|-----|------|
| C12 | `isRefSubtypeOf` now takes the module and compares concrete refs **structurally** (iso-recursive typing): two concrete refs are related iff their referenced types are equivalent after unrolling, with coinductive cycle handling and positional identity within rec groups (matching `tag.wast` assert_unlinkable and `type-equivalence.wast`). Previously any `(ref $a)` was a subtype of any `(ref $b)`, letting `call_ref` execute under the wrong signature. | `TestIsRefSubtypeOfConcreteRefs`, spec `type-equivalence.wast`, `tag.wast` |
| C13 | All four import comparisons (func, table, global, tag) now compare concrete-ref-carrying types **structurally across the two modules** (`valueTypesEquivalentAcrossModules` / `isRefSubtypeOfAcrossModules`), replacing both raw `ValueType` equality (module-local index bits) and the store's type-ID keying (whose rec-group key construction is the [0706-U23] hazard). Also fixes the false-reject direction for cross-index imports. | `TestE2E_concrete_ref_table_import` |
| C14 | Exception params are slot-packed (`wasm.ExceptionParamSlots`: 1 uint64 per scalar, 2 per v128) in alloc (`call_engine.go`), throw stores (frontend: one 16-byte store per v128) and catch loads (`loadExceptionParams`). The interpreter's `operationKindThrow` pops v128 params as lo/hi pairs. Previously a v128 tag param wrote 16 bytes into an `nParams`-element `[]uint64` — a Go heap overflow. | `TestE2E_throw_v128_param` (both engines) |
| C15 | Every thrown exception is rooted in the `Store` for its lifetime (`ModuleInstance.KeepExceptionAlive`, called at both creation sites). Guest-held exnrefs are raw pointers the Go GC cannot see; without a root, `throw_ref` of a saved exnref could read freed memory. Trade-off (documented): exceptions are retained for the store's lifetime. | `TestE2E_exnref_gc_root` (pins correct behaviour; the unrooted failure is probabilistic, as with any GC bug) |

Supporting change: `internal/testing/binaryencoding` now encodes concrete reference types properly (`EncodeValueType`); `EncodeTable`/`EncodeImport`/`EncodeGlobal` previously wrote only the kind byte, silently dropping the ref prefix and type index (latent test-helper bug surfaced by the new tests).

### Not yet addressed

- **C19–C81** (Medium/Low as tabulated in §1) — unchanged.

### Fixed this session, part 3 (Medium/Low sweep)

All verified: `go build ./...` clean; `go vet ./...` only the pre-existing (by-design) io-interface
name collisions — C78's asm arg-name mismatches are fixed; `go test ./...` green; golangci-lint 0 issues.

| ID | Fix |
|----|-----|
| C19 | `FSContext.OpenFile`/`SockAccept` cap the descriptor table (`EMFILE` beyond `maxFileDescriptor`); `lazyDir.file()` no longer panics on resource errors (e.g. fd exhaustion) — it surfaces as a guest-visible error. New `sys.EMFILE` errno (appended, no value shifts) with wasip1 mapping. |
| C20 | `tcpConnFile.close()` now actually closes the `*net.TCPConn` (it delegated to `Shutdown(SHUT_RDWR)` which recursed into the already-flagged `close()` — every `fd_close` of an accepted connection leaked the socket). `Shutdown(SHUT_RDWR)` now does a faithful both-direction shutdown without closing the fd. |
| C21 | Multi-iovec `fd_read`/`fd_write` return the bytes transferred before an error (POSIX readv/writev semantics), so retries don't duplicate or lose partial transfers. |
| C22 | `stdioFile` blocks `Truncate`, `Pwrite` (ESPIPE) and `Utimens` — the guest can no longer truncate, sparsely extend, offset-write or re-time the embedder's stdio. New `sys.ESPIPE` errno. |
| C23 | `validateTagSection` runs before `validateFunctions` (a defined tag with an out-of-range type index panicked in throw/try_table validation); `ref.func` bounds-checks the function index before the declared check (an elem-"declared" out-of-range index panicked). One existing test's expectation updated (it relied on the buggy order). |
| C24 | The table element type must be a reference type: any byte (i32, v128, garbage) was previously accepted. |
| C25 | Concrete reference value types (`0x63`/`0x64`) in params, results, locals, globals and global imports now require `CoreFeaturesTypedFunctionReferences`. |
| C26 | A corrupt/truncated cache entry is deleted and treated as a miss (previously `CompileModule` failed permanently); the mmapped code segment is unmapped on every deserialize error path; the (non-CRC'd) header function count is sanity-capped. |
| C27 | A failed cache *write* no longer fails `CompileModule` — the module is live in memory and simply not cached. |
| C28 | Listener slices and trampolines are attached **before** the module is published to concurrent instantiations. |
| C29 | Cache-hit modules compile their entry preambles **before** being published, so a concurrent `ExportedFunction` cannot read the empty preambles table. |
| C33 | `DWARFLines.Line` nil-guards `LineEntry.File` and inlined file entries: malformed `.debug_line` no longer crashes the host inside the trap formatting path. |
| C34 | The listener factory participates in the module ID (per-process pointer identity): a second compile with a different factory recompiles instead of replaying the first factory's listeners. |
| C35 | `multiFunctionListener` captures the stack once per `Before` and hands each listener its own iterator (the embedded one raced across listeners/goroutines). |
| C36 | `InstantiateModule` closes the sys context (releasing bound TCP listeners) on every failure after `toSysContext`. |
| C37 | `compiledModule.Close` is idempotent (`sync.Once`): the refcount shared by all handles of a module ID can no longer be double-decremented. |
| C38 | An `ImportResolver` returning a closed module is rejected instead of linked and called. |
| C39 | Duplicate-name registration is pre-checked before instantiation (the start function no longer runs for a name that will fail registration), and `deleteModule` only removes the name entry it owns. |
| C41 | Use-after-close returns errors instead of panicking on nil maps: the store rejects `GetFunctionTypeIDs` after close, and the wazevo engine rejects `CompileModule`/registration after close. |
| C45 | Constant expressions may only `global.get` **immutable** globals (imports and, under extended-const, defined ones) — data offsets no longer depend on instantiation order or diverge between engines. |
| C47 | `fd_renumber(fd, fd)` is a no-op (it used to close the fd). |
| C48 | `path_symlink` copies the link target out of guest memory before handing it to the FS (no more live-guest-memory `unsafe.String`). |
| C49 | `fd_filestat_set_times` no longer dereferences a nil `f.FS` for stdio/socket fds. |
| C50 | `sock_accept` closes the accepted connection when the result cannot be written back (EFAULT no longer leaks the fd). |
| C54 | Element segments are applied before data segments (spec instantiation order). |
| C55 | Memory imports reject a shared/non-shared mismatch. |
| C56 | `GlobalInstance.String()` reads the engine-owned value (`Value()`), and names v128/ref globals instead of panicking. |
| C58 | `Store.CloseWithExitCode` snapshots the module list under the lock and closes the modules outside it, so `CloseNotifier` callbacks may call back into the store without deadlocking. |
| C59 | The re-exported-table `involvingModuleInstances` append takes the same mutex as the import path. |
| C61 | Shared-cache engines are keyed by (engine kind, core features): a second Runtime with different features no longer silently reuses an engine compiled under the first Runtime's features. |
| C63 | `InstantiateModule` returns a nil module whenever it returns an error after `_start` failed (no more non-nil closed module). |
| C64 | `Errno.Unwrap` maps `ERANGE` (previously fell through to EIO, making `errors.Is(ERANGE, syscall.EIO)` true). |
| C65 | The CLI clamps guest exit codes >125 (shell wraps mod 256: `proc_exit(256)` exited 0). Host sentinel codes (cancel/deadline) pass through unchanged. |
| C66 | The CLI `-timeout` deadline starts after compilation (the flag's documented semantics); `WithCloseOnContextDone` is still enabled upfront so the guest observes it. |
| C68 | RATIONALE.md context-cancellation section rewritten to describe the fork's actual design (inline native check + periodic Go yield). |
| C69 | Upstream issue links broken by the import-path rename restored (4 files). |
| C76 | `lowerSelect` marks the Icmp lowered (`MarkLowered()`, not the `Lowered()` getter) — the Icmp was lowered twice. |
| C78 | asm arg names in `abi_entry_{amd64,arm64}.s` match the Go declarations (`go vet` asmdecl clean). |
| C79 | `osFile.reopen` closes the freshly opened file when `checkSameFile` fails (fd leak). |

### Fixed this session, part 4 (remaining Low sweep)

All verified: suite green, golangci-lint 0 issues, `go vet` asmdecl clean.

| ID | Fix |
|----|-----|
| C31 | The load-CSE store scan is now bounded: the cache is cleared past `maxLoadCSECacheEntries` (512) tracked accesses per block, which only forfeits reuse and never affects correctness. The 80k-store pathological block that took 31.9 s now takes ~30 ms (benchmark included in `pass_load_cse_bench_test.go`). Root-bucketing was attempted first and **rejected as unsound**: different roots are assumed to potentially overlap, so a store must invalidate entries of every root. |
| C30 (partial) | `TableInstance.Grow` refuses growth beyond `MaximumTableIndex` (spec permits arbitrary grow failure): a guest could previously request ~2³² entries and fatally OOM the host on the append. Also, wazevo's `ref.func` trampoline now reuses one `functionInstance` per function (the contents are static per (module, funcIndex)): a guest calling `ref.func` in a loop previously appended a new instance per iteration and leaked host memory without bound. The try_table stack-clone component remains deferred (limits-API design). |
| C44 | All remaining unmasked i32 consumers in the interpreter now mask (`maskUint32`): `br_if`, `br_table`, `select`, `call_indirect` (+ tail-call variant) indices, `table.get/set/grow/fill/init/copy` and `memory.init/copy/fill`. Loads/stores were already masked (#2488). |
| C46 | `poll_oneoff` size arithmetic can no longer wrap (huge `nsubscriptions` returns EINVAL instead of producing out-of-bounds event writes); the remaining-time budget is clamped to the int32 the Poll API takes; `_poll(-1)` now blocks indefinitely (ppoll with nil timeout) instead of returning immediately. |
| C51 | `fd_prestat_get`/`fd_prestat_dir_name` on a preopen-flagged non-directory (stdio, TCP listeners) returns EBADF instead of success with an empty name — the guest no longer believes fd 0 is a preopened directory. |
| C52 | Self tail calls (`return_call $self`) now emit the termination check on both engines: they never pass a loop header, so self-recursion previously ran forever under `WithCloseOnContextDone`. The wazevo check is extracted into `lowerTerminationCheck` and reused. Verified: test fails pre-fix (10 s hang) and passes post-fix. |
| C53 | The interpreter `Snapshot` records the current frame's pc (Restore used to restart at pc 0). |
| C57 | Reflection host funcs marshal float32 params/results bit-preservingly (via `reflect.Value.Addr`/`UnsafePointer`): `SetFloat`/`Float()` round-tripped through float64 and quieted signalling NaNs. Verified: test fails pre-fix. |
| C67 | `CompilerSupported` additionally requires the POPCNT CPUID bit: the amd64 backend emits POPCNT unconditionally for `ssa.OpcodePopcnt`, and SSE4.1 does not imply it. |
| C70 | The load-CSE pointer decomposition now peels `UExtend(Iconst)` — the form the frontend emits for wasm memory indices — so the documented `memoryBase + const` decomposition actually fires for wasm memory. Unit test on `decomposePointer` included. |
| C75 (partial) | The threads-proposal atomic alignment check drifted: ~30 atomic cases used `<= natural` where the spec requires exact alignment. **Attempted and reverted**: tightening breaks real TinyGo modules (this repo's own `add.wasm` testdata uses under-aligned atomics), so real-world compatibility wins; documented here rather than fixed. |
| C80 (partial) | Bare `wazero` invocation exits 1 (was 0, indistinguishable from success); `run`/`compile` surface flag-parse errors instead of silently continuing with Go's flag output. Dev-flag hiding and the `compile`-without-`--cachedir` note remain. |
| C81 | `CloseNotifier` and `CodeCloser` are attached inside `Store.Instantiate` before the module becomes visible via `registerModule` (plumbed as parameters; ~40 test call sites updated). |

### Deferred (with reasons)

- **C30** (guest-driven unbounded host memory: `ref.func` leak, try_table stack clones, unbounded `table.grow`) — needs a capacity-policy design (limits API), not a local fix.
- **C32 (remainder)** — the loop-nesting forest build was fixed (memoized, O(blocks)); the redundant-phi fixpoint already converges globally with a documented worst case (22 iterations on sqlite), so no further change was made without a pathological reproducer.
- **C42** — investigated: the drop-range off-by-one could not be made observable in any validation-legal shape I constructed (junk stays below the label args in every reachable configuration). The behavioral change I attempted was reverted for lack of a failing test; the multi-result `br_on_non_null` e2e test added in `br_on_non_null_multi_result_test.go` pins current behaviour. Needs the auditor's exact repro.
- **C43** (Windows overlapped socket I/O) — Windows-only; fixed by inspection is possible but unverifiable here. Left as-is.
- **C30 (remainder)** — try_table whole-stack clones per entry: needs a capacity-policy design (limits API).
- **C42** — investigated: the drop-range off-by-one could not be made observable in any validation-legal shape I constructed (junk stays below the label args in every reachable configuration). The behavioral change I attempted was reverted for lack of a failing test; the multi-result `br_on_non_null` e2e test added in `br_on_non_null_multi_result_test.go` pins current behaviour. Needs the auditor's exact repro.
- **C43** (Windows overlapped socket I/O) — Windows-only; fixed by inspection is possible but unverifiable here. Left as-is.
- **C62** (host modules surface as three types by path) — API-design work.
- **C72** (fork test gaps) — the 630d3404 re-intern gap is covered by the cross-Runtime tests added this session (`TestE2E_cross_runtime_*`); the arm64 golden trap-island tests remain skipped on amd64 hosts.
- **C74 (remainder)** — the LookupFunction panic message was fixed; the remaining divergences (wazerotest memory semantics details, decorative examples) need the auditor's §3 specifics, which were never written.
- **C77** — latent (unreachable) codegen hazards; documented for a future sweep.
- **C75 (remainder)** — signed LEB over-accept, `ref.null` heap type decoding, `(ref null $t)` table rejection by `call_indirect`, empty datacount at EOF, data-vs-elem offset rules; each is a conformance-vs-compatibility trade-off needing spec-test verification.
- **C71** — applies to an unmerged branch, not `main`.
- **C71** — applies to an unmerged branch, not `main`.
