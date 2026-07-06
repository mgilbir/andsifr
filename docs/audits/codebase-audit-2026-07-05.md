# Codebase Audit — andsifr (wazero fork) — 2026-07-05

**Auditor stance:** adversarial; no loyalty to the current design.

**Scope decision.** `andsifr` is a fork of `tetratelabs/wazero` (~178 k LOC). Auditing all of upstream
adversarially is neither feasible nor useful — it is a mature, heavily-reviewed runtime. This audit targets
the **fork delta** (the commits on top of fork point `9a9d5440`) as the primary object, and treats the public
API surface a first-time embedder touches as the secondary object. Findings are tagged **[FORK]**
(introduced or materially amplified by this fork — the maintainer's direct responsibility) or **[UPSTREAM]**
(pre-existing in wazero, surfaced here for completeness).

The fork delta splits into: **novel work** — `52158144`, `25ea61ec` (pre-applied memory images), `755df6b5`
(engine-cache RLock), `5c0c6e9c` (SSA load-CSE), `fd1cb8f3` (arm64 scaled-index folding), `3bde8fa4` (inline
loop-header termination) — and **upstream backports** (`#2481`, `#2504`, `#2506`, `#2508`, `#2512`), which are
inherited and reviewed upstream.

**Verification note.** C1 and C2 (the two highest-severity fork findings) were traced by hand to the exact
lines. Findings tagged _(agent-reproduced)_ were empirically reproduced with runnable code by a verification
sub-agent; findings tagged _(traced)_ were confirmed by code reading. `go build ./...` is clean, zero stale
`tetratelabs/wazero` import paths remain, and the SSA/arm64/frontend/wazevo test suites pass.

---

## 1. Summary table

| ID  | Sev | Prov | Area | One-line issue | Location | Status |
|-----|-----|------|------|----------------|----------|--------|
| C1  | High | FORK | arm64 codegen | Negative residual offset dropped in scaled addressing → wrong runtime address | `internal/engine/wazevo/backend/isa/arm64/lower_mem.go:330` | CONFIRMED |
| C2  | High | FORK | Pre-applied memory | Start function re-runs against a post-start image → silent wrong guest memory | `internal/wasm/store.go:442-460` | CONFIRMED |
| C3  | High | UPSTREAM | Config | `ModuleConfig.WithEnv` aliases the env backing array; sibling forks corrupt each other | `config.go:701-708,729-739` | CONFIRMED |
| C4  | High | UPSTREAM | Import path | `ImportResolver` returning a host module panics (type assertion) | `internal/wasm/store.go:471` | CONFIRMED |
| C5  | Med | FORK | Pre-applied memory | Doc invites capturing "a previously initialized instance's memory" — the wrong state | `experimental/memory.go:45-71` | CONFIRMED |
| C6  | Med | FORK | Pre-applied memory | Doc says moduleID = "SHA-256 of the binary"; the ID also hashes flags, so `sha256(binary)` never matches | `experimental/memory.go:53` vs `internal/wasm/module.go:214-230` | CONFIRMED |
| C7  | Med | FORK | DX / docs | Pre-applied + inline-cancellation features have zero user-facing docs/examples | repo-wide | CONFIRMED |
| C8  | Med | FORK-amp | Lifecycle | Start-trap during instantiate leaks the custom-allocator memory image + sys FS | `internal/wasm/store.go:375-385` | CONFIRMED |
| C9  | Med | UPSTREAM | listener API | `NewStackIterator` pairs each frame's PC with the wrong function definition | `experimental/listener.go:274-292` | CONFIRMED |
| C10 | Med | UPSTREAM | Config race | `InstantiateModule` mutates the "immutable" `ModuleConfig` (sockConfig) → rebind + data race | `runtime.go:319-324` | CONFIRMED |
| C11 | Med | UPSTREAM | test helper | `wazerotest.Memory.WriteUint64Le` bounds-checks 4 bytes but writes 8 | `experimental/wazerotest/wazerotest.go:597-603` | CONFIRMED |
| C12 | Med | UPSTREAM | logging | Logging-listener factory shares one stack across goroutines → race/panic | `experimental/logging/log_listener.go:91,154` | CONFIRMED (sharing) |
| C13 | Med | UPSTREAM | fsconfig | `WithFSMount(nil, path)` override stores a nil FS that reaches a preopen | `fsconfig.go:184-198` | CONFIRMED (to instantiate) |
| C25 | Med | FORK | File cache | Try-table metadata sits outside the CRC; a same-version ("dev") stale entry misparses → unbounded `make()` OOM + wrong-sized locals save-area corruption | `internal/engine/wazevo/engine_cache.go:328-341` | CONFIRMED |
| C27 | Med | FORK | Interpreter | Carried overflow fix (#2506) is incomplete: `ReadUint16Le` and `Read` still wrap `offset+N` → Go panic instead of clean trap | `internal/wasm/memory.go:129,165` | CONFIRMED |
| C14 | Low | FORK | Pre-applied memory | `hasImportDependentDataOffsets` indexes `m.Globals` without the bounds guard its sibling has | `internal/wasm/store.go:320` | PLAUSIBLE |
| C15 | Low | FORK | Pre-applied memory | Doc/name says "imported global" but the check refuses on *any* global | `internal/wasm/store.go:305-334` | CONFIRMED |
| C16 | Low | FORK | Pre-applied memory | Skip gate doesn't require the module to *own* the memory | `internal/wasm/store.go:283-288` | PLAUSIBLE |
| C17 | Low | FORK | Pre-applied memory | Offset const-exprs evaluated twice on the skip path | `internal/wasm/store.go:285,293` | CONFIRMED |
| C18 | Low | FORK | Host modules | `hostModuleBuilder.Compile` never sets `compiledStore` → typeIDs re-interned every instantiation | `builder.go:327` | CONFIRMED |
| C19 | Low | FORK | wazevo | `WithCompilationWorkers>1` honors ctx cancellation; serial path ignores it | `internal/engine/wazevo/engine.go:264-330` | CONFIRMED |
| C20 | Low | UPSTREAM | Host modules | `hostModuleBuilder.Compile` skips `failIfClosed` → compiles into a closed runtime, leaks | `builder.go:319-345` | CONFIRMED |
| C21 | Low | UPSTREAM | Cache | `cache.Close` returns on first engine error, leaking the others | `cache.go:77-86` | CONFIRMED |
| C22 | Low | UPSTREAM | Allocator | `MemoryAllocator`/`Reallocate` returning nil/short panics instead of erroring | `internal/wasm/memory.go:76-80` | CONFIRMED |
| C23 | Low | UPSTREAM | Docs | Six doc examples/statements that don't compile or misstate behavior (bundled) | see §3.23 | CONFIRMED |
| C24 | Low | FORK | DX / drift | Dead `CODEOWNERS` + residual upstream refs in badge/site/CI | `.github/CODEOWNERS`, `site/`, `README.md` | CONFIRMED |
| C26 | Low | FORK | wazevo perf | Cancellation-enabled loop bodies lose known-safe-bounds → every bounds check re-emitted + extra phis | `internal/engine/wazevo/frontend/lower.go:1366-1439` | CONFIRMED |
| B1  | Low | FORK | SSA load-CSE | Invalidation is an opcode whitelist; correct today, silently fragile to new memory-writing opcodes | `internal/engine/wazevo/ssa/pass_load_cse.go:48-77` | PLAUSIBLE (latent) |

**Counts:** High 4 (2 FORK, 2 UPSTREAM) · Medium 11 · Low 13 (incl. the latent B1). IDs C25–C27 were added after later verification
passes and appended (not renumbered) to keep earlier IDs stable for a fixing agent; the table remains
severity-ordered. The SSA load-CSE pass (`5c0c6e9c`) has **no confirmed miscompilation** — its conservative
design was independently traced hazard-by-hazard by two reviewers and holds (see §3.B1). Verification agents
also independently reconfirmed C1 (arm64), C2 (start-function image), C6 (moduleID doc), and C25 (cache
format), and cleared a large set of adversarial hypotheses.

**Backports verified clean (no finding):** `#2508` (arm64 IRem garbage-register — the `copyToTmp` before the
exit sequence correctly breaks the live range on every path, incl. div-by-zero trap and `INT_MIN%-1`);
`#2504` try_table locals save/restore *logic* (the corruption is in the cache path C25, not the runtime
save/reload); `#2481` poll_oneoff (shared time budget, no busy-wait, no fd leak — one pre-existing, non-fork
`int32(remaining.Milliseconds())` quirk that caps an "infinite" blocking-fd wait at ~24 days, not a hang).
Compiler-engine spectest v2 + threads + EH + extended-const + tail-call all pass; a `-race` stress of
concurrent instantiate/compile/close is clean.

---

## 2. System map

**Pipeline.** `NewRuntime` → `CompileModule` (decode → `Module.Validate` → `AssignModuleID` → engine
compile) → `InstantiateModule` → `Store.instantiate` (`store.go:388`), which builds the instance in a fixed
order:

```
resolveImports → buildTables → buildGlobals → buildTags → buildMemory
   → validateData (only if reference-types feature OFF)
   → buildElementInstances → applyData → applyElements → start function → registerModule
```

**Module identity.** `AssignModuleID` (`module.go:214`) sets `Module.ID = SHA-256(binary ‖ per-function
listener-presence flags ‖ ensureTermination byte)`, computed **unconditionally** (not gated on the file
cache). So identity is never a shared zero value — the safety backbone of the pre-applied feature — but it is
**not** `sha256(binary)` (see C6).

**Pre-applied memory skip (novel).** In `applyData` (`store.go:282-288`) active-segment copies are skipped
iff *all* of: memory has an `expBuffer` and is not `Shared`; `expBuffer` implements
`experimental.MemoryWithPreappliedData`; no active offset reads a global (`hasImportDependentDataOffsets`);
and `PreappliedDataFor(m.Source.ID)` returns true. Bounds are still validated and passive `DataInstances`
still registered on the skip path. Memory is freed on close only by the owning engine (`module_instance.go:158`,
backport `#2512`) — composes correctly with a CoW view.

**Inline termination (novel, `3bde8fa4`).** `execCtx` carries `entryModuleClosedPtr *atomic.Uint64` (=
`&entryModule.Closed`) and `terminationCheckCounter int64`. Loop headers load `*closedPtr`, decrement the
counter, and take the check-module-exit-code trampoline slow path only when `closed != 0 || counter <= 0`,
resetting the counter to `1<<16` so a tight loop still yields to the Go scheduler periodically. Traced; sound.

**Engine-cache RLock (novel, `755df6b5`).** The instantiation read path takes `RLock`; the map holds
`*compiledModuleWithCount` pointers and `refCount` is mutated only under the write `Lock`, which the read path
never touches. Race-free. Sound.

**Key invariants.** (i) `applyData` is the only place active data is copied, and runs *before* the start
function — C2 breaks the assumption behind pre-applied images. (ii) One live instance per non-empty name
(`registerModule`, write-locked). (iii) Each `MemoryInstance` owned by exactly one engine; only the owner
frees `expBuffer` — the *skip* gate does not consult this (C16). (iv) Const-expr offsets are validated in
`Module.Validate` before runtime; runtime evaluators then run unchecked (C14 adds a second unguarded
consumer).

---

## 3. Findings (severity order)

### C1 — [FORK] arm64: negative residual offset dropped in scaled addressing mode — High — CONFIRMED
**`internal/engine/wazevo/backend/isa/arm64/lower_mem.go:329-332`** (commit `fd1cb8f3`).

**Should:** when a left-shifted index is folded into a scaled addressing mode (`[rn, rm, LSL #k]`), that mode
has **no immediate offset field**, so any leftover constant `offset` must be added into the base register.

**Reality:** the fold only handles positive offsets:
```go
baseReg := amode.rn
if offset > 0 {
    baseReg = m.addConstToReg64(baseReg, offset)
}
```
A **negative** `offset` is silently discarded. The a64s-empty arm just above (`:317-321`) materializes any
offset (incl. negative) into the base and is fine; the broken case is *scaled index + at least one 64-bit base
addend + negative constant offset*.

**Concrete failure:** guest expression `(i64.load (i64.add (i64.add $p (i64.shl $i (i64.const 3)))
(i64.const -8)))` (a memory64 `p + i*8 - 8` pointer, the shape a compiler emits for `&arr[i-1]`). `collectAddends`
yields base `$p`, a shifted addend `$i<<3`, and `offset = -8`. Because the shift matches the 8-byte access,
the scaled mode wins, and `-8` is dropped → emitted `ldr x?, [p, i, LSL #3]`, computing `p + i*8`; the correct
address is `p + i*8 - 8`. **Wrong load/store address at runtime, no trap, silent data corruption.** The same
drop triggers for any i64 constant addend ≥ 2^63 (negative as int64) or a merged `SExtend` of a negative i32
constant. _(agent-reproduced through `lowerToAddressModeFromAddends`; I re-traced the branch by hand.)_

This is *newly reachable via the scaled-index path*: before this commit the shift was an ordinary 64-bit
addend and `p + i*8 - 8` took the `RegSignedImm9` branch (`:357`), which encodes `-8` correctly.

**Direction:** change the guard to `if offset != 0` in the scaled branch (`addConstToReg64` already handles
negative constants, as the a64s-empty arm relies on). The identical `if offset > 0` at `:398` in the
non-scaled RegExtended fallthrough shares the pattern and deserves the same fix + a test. Add coverage for
negative offsets with a scaled index, SXTW folds, and shift-4/V128 (currently unreachable — see §note).

_Note:_ `sizeInBitsToShiftAmount` (`lower_mem.go:181-193`) has no `case 128`, returning 0 for V128, so
shift-4 addends never match — the commit message's claim that k=4 folds is dead code (missed optimization,
not a bug).

### C2 — [FORK] Start function re-executes against a post-start pre-applied image — High — CONFIRMED
**`internal/wasm/store.go:442-460`; interface doc `experimental/memory.go:45-71`** (commits `52158144`,
`25ea61ec`).

**Should:** a "pre-applied" image must be bit-identical to normal-instantiation memory *at the point the copy
would happen* — i.e. after data segments, **before the start function** and before any guest execution.

**Reality:** `instantiate` always runs the module's start function (`:451-459`) after `applyData`, on every
instance, skip or not. The interface doc tells the host the image may be "a copy-on-write view of the memory
of a previously initialized instance of that module" (`memory.go:48-50`) — a state that has *already run its
start function*.

**Concrete failure:** module has a `start` section that increments a counter at address 0 (one-time global
init; common in TinyGo/Rust output). Instance #1: data sets `mem[0]=0`, start → `mem[0]=1`; host snapshots
this as the CoW image. Instance #2 with the image: data-copy skipped so `mem[0]` starts at `1`, then start
runs **again** → `mem[0]=2`. A fresh instance should see `1`. **Silent wrong guest state, no error.** The
module-ID match is satisfied (same binary), so nothing refuses the skip.

This is exactly the "silent-wrong-output class of misuse" commit `25ea61ec` set out to close — it closed the
*spatial* axis (wrong binary, via module ID) but left the *temporal* axis (wrong capture point) as a prose
rule, the very structure that commit argues against.

**Direction:** make it structural — refuse the skip when `module.StartSection != nil` (cheap, matches the
commit's own philosophy). Independently, rewrite the doc (C5).

### C3 — [UPSTREAM] `ModuleConfig.WithEnv` aliases the env backing array — High — CONFIRMED
**`config.go:701-708` (`clone`), `:729-739` (`WithEnv`).** `clone()`'s "deep copy" appends to an `environ`
slice sharing capacity with the parent. `base := NewModuleConfig().WithEnv("A","1").WithEnv("B","2").
WithEnv("C","3")` (len 6, cap 8); then `c1 := base.WithEnv("D","4"); c2 := base.WithEnv("E","5")` — both
appends write the *same* backing slots, so `c1` and `c2` both end up with `E=5` and `D=4` is lost.
Cross-config env corruption; in a multi-tenant server one tenant's env can leak into another's module.
`WithNanosleep`/`WithOsyield` (`:824-835`) don't even call `clone()`. _(agent-reproduced.)_ **Direction:**
copy `environ` at exact `len==cap` in `clone()`, as `fsConfig.clone` already does.

### C4 — [UPSTREAM] `ImportResolver` returning a host module panics — High — CONFIRMED
**`internal/wasm/store.go:471` (`v.(*ModuleInstance)`), contract `experimental/importresolver.go`.** Host
modules returned by `HostModuleBuilder.Instantiate`/`Runtime.Module` are `wazero.hostModuleInstance`
wrappers, not `*wasm.ModuleInstance`. Returning one from an `ImportResolver` panics
(`interface conversion: api.Module is wazero.hostModuleInstance, not *wasm.ModuleInstance`) instead of
erroring; nothing documents the restriction. _(agent-reproduced.)_ **Direction:** unwrap the host wrapper in
the resolver path, or return a typed error.

### C5 — [FORK] Interface doc describes the wrong memory state to capture — Medium — CONFIRMED
**`experimental/memory.go:45-71`.** The doc says both "already include the active data segments" (pre-start)
and "a copy-on-write view of the memory of a previously initialized instance" (post-start). These are
different contents (C2). A first-time integrator reading only this doc builds the wrong image. **Direction:**
one unambiguous definition ("memory immediately after data-segment application") plus an explicit non-example
("do **not** snapshot an instance you have executed").

### C6 — [FORK] moduleID doc says "SHA-256 of the binary"; the real ID hashes more — Medium — CONFIRMED
**`experimental/memory.go:53` vs `internal/wasm/module.go:214-230`.** `AssignModuleID` hashes the binary
**plus** per-function listener-presence flags **plus** an `ensureTermination` byte. So `sha256(binary)` — the
only value the doc invites an embedder to compute — never equals `m.Source.ID`, and the ID changes when
`WithCloseOnContextDone(true)` or a listener factory is toggled. An embedder following the doc literally
returns false forever and the optimization silently no-ops (fail-safe, but the flagship feature is dead). The
one working protocol — capture the ID handed to `PreappliedDataFor` during the template instantiation and bind
it to the image — is undocumented, and no API otherwise exposes the ID. _(traced.)_ **Direction:** correct the
doc; document the capture-on-first-call protocol, or expose the identity on `CompiledModule`.

### C7 — [FORK] New experimental features are undocumented outside Go doc comments — Medium — CONFIRMED
No `README`, `RATIONALE.md`, `site/`, or `examples/` mention `MemoryWithPreappliedData` or the changed
cancellation behavior. Given C2's footgun, a worked example is close to mandatory. **Direction:** add an
`examples/` entry showing the correct capture point + the `PreappliedDataFor` keyed on module ID, and a
RATIONALE note on *why* the ID binding exists.

### C8 — [FORK-amplified] Start-trap during instantiation leaks the memory image + FS — Medium — CONFIRMED
**`internal/wasm/store.go:375-385`, `runtime.go:346-353`.** If `s.instantiate` fails after `buildMemory` (e.g.
the wasm start function traps), the partial `m` — with `m.MemoryInstance.expBuffer` allocated and `m.Sys`
assigned — is discarded without `Close`; `expBuffer.Free()` and `sysCtx.FS().Close()` never run. Inherited,
but directly amplified by the fork's target workload (instantiate-per-request with pooled/CoW allocators):
**every start-trap leaks a memory image.** _(traced.)_ **Direction:** on `instantiate` error, free owned
`expBuffer` and close `Sys.FS()` (a `defer` cleanup guarded until successful registration).

### C9 — [UPSTREAM] `NewStackIterator` pairs PCs with the wrong functions — Medium — CONFIRMED
**`experimental/listener.go:274-292`.** `si.stack` is reversed (top last) but `si.fndef` is filled from the
unreversed argument, so `Function()` and `ProgramCounter()` come from opposite ends. A 2-frame stack yields
`fn=bottom pc=top-pc` then `fn=top pc=bottom-pc`. _(agent-reproduced.)_ **Direction:** derive `fndef[i]` from
the already-reversed `si.stack`.

### C10 — [UPSTREAM] `InstantiateModule` mutates the immutable `ModuleConfig` — Medium — CONFIRMED
**`runtime.go:319-324`.** It writes `config.sockConfig` in place from a ctx value. Consequences: (a) a config
used once with a sock ctx keeps binding host ports on every later instantiation; (b) two goroutines
instantiating with the same `ModuleConfig` (an explicitly supported pattern) race on the unsynchronized
field. _(traced.)_ **Direction:** clone the config or thread `sockConfig` alongside it, not through it.

### C11 — [UPSTREAM] `wazerotest.Memory.WriteUint64Le` bounds-checks the wrong size — Medium — CONFIRMED
**`experimental/wazerotest/wazerotest.go:597-603`** checks 4 bytes but writes 8: `NewMemory(PageSize).
WriteUint64Le(PageSize-5, v)` panics with an out-of-range index instead of returning false. _(agent-reproduced.)_
**Direction:** `isOutOfRange(offset, 8)`.

### C12 — [UPSTREAM] Logging-listener factory shares one stack across goroutines — Medium — CONFIRMED (sharing)
**`experimental/logging/log_listener.go:91,154`.** One `logStack` is shared by every listener the factory
creates. Concurrent guest calls race on `params` append/pop; interleaving can `pop()` an empty slice (panic)
and garble indentation/params. Nothing documents single-threaded-only. **Direction:** document, or key the
stack per call-context.

### C13 — [UPSTREAM] `WithFSMount(nil, path)` override stores a nil FS reaching a preopen — Medium — CONFIRMED (to instantiate)
**`fsconfig.go:184-198`.** The nil-FS guard exists only on the new-path branch; overriding an existing
guestPath with `fs == nil` stores nil, which flows into a preopen `FileEntry{FS: nil, File: &lazyDir{fs:nil}}`.
Instantiation succeeds; the first `path_open`/`fd_readdir` through it dereferences nil. _(agent-reproduced to
instantiation.)_ **Direction:** treat nil as "remove mount" or reject in both branches.

### C25 — [FORK] Try-table cache metadata is unprotected; a stale same-version entry OOMs — Medium — CONFIRMED
**`internal/engine/wazevo/engine_cache.go:328-341`** (serialize `:197-213`; format changed by backport
`#2504`).

**Should:** a serialized-format change must be detectable, and any length read from a cache file before an
allocation must be integrity-checked or capped.

**Reality:** the on-disk try-table metadata format changed within the fork's own history
(catch-clause-table → `tryTableInfo` with a 5-byte per-entry header). The only staleness guard is the version
string, which is `internal/version.Default = "dev"` for any build from source (`version.go:9`) — i.e. *every*
fork build shares it unless a release ldflag is set. The trailing metadata (source map + try-table) is **not**
covered by the CRC (`crc32.Checksum` runs over `cm.executable` only, `:282`), and there is **no sanity cap**
before allocation:
```go
tableLen := binary.LittleEndian.Uint32(eightBytes[:4])   // :328
cm.tryTableInfo = make([]wazevoapi.TryTableInfo, tableLen) // :330 — up to ~2^32 * ~32 B
...
clauseCount := binary.LittleEndian.Uint32(eightBytes[:4]) // :340
clauses := make([]wazevoapi.CatchClauseInstance, clauseCount) // :341 — up to ~2^32 * ~8 B
```
The graceful-stale path at `:324-327` only catches a *clean EOF* (try-table section entirely absent); it does
not catch a *different* old layout that mis-aligns the reader.

**Concrete failure:** an embedder uses a persistent `WithCompilationCache(NewCompilationCacheWithDir(dir))`,
compiles modules with fork build A (try-table format A, version "dev"), then upgrades to fork build B (format
B, still "dev") reusing `dir`. Deserializing an A-format entry: version matches, executable + CRC validate,
then the reader is mis-aligned at the metadata; `tableLen`/`clauseCount` read as garbage up to 4 billion →
multi-GB `make()` → **OOM crash** (or, for small-but-wrong counts, silently wrong catch-dispatch metadata
baked into exception handling). CONFIRMED (format divergence traced across revisions; version="dev" confirmed;
allocation is unbounded; independently reproduced by a second reviewer). A second corruption path was traced
alongside the OOM: the 5-byte-per-entry misalignment also yields a wrong `NumLocals`, which drives a
wrong-sized locals save-area allocation at runtime → memory corruption/crash in the exact exception-handler
path `#2504` set out to fix. **Direction:** add a dedicated format-version byte to the payload (independent of
the wazero version string), extend the CRC over the metadata, and/or cap `tableLen`/`clauseCount` and treat
overflow as `staleCache`.

### C27 — [FORK] Carried interpreter overflow fix (#2506) is incomplete — Medium — CONFIRMED
**`internal/wasm/memory.go:129` (`ReadUint16Le`), `:165` (`Read`)** (fix commit `4e6bf9b1`).

**Should:** on a load near the top of the address space, the slice upper bound must not wrap in `uint32`, so
an out-of-range access returns `false` (clean wasm trap), matching what the stores already do.

**Reality:** commit `4e6bf9b1` fixed exactly `readUint32Le` and `readUint64Le` (→ `m.Buffer[offset:]`) but its
commit message ("Issue only affects loads") overlooked two more loads with the identical `uint32` wrap:
```go
binary.LittleEndian.Uint16(m.Buffer[offset : offset+2])          // :129 ReadUint16Le
m.Buffer[offset : offset+byteCount : offset+byteCount]           // :165 Read
```
`hasSize` uses `uint64` and passes; the slice expression uses `uint32` and wraps. `ReadUint16Le` is reached by
the interpreter's `i32.load16_*` (`interpreter.go:1039`) and 16-bit atomic loads; `Read` by atomic ops and
every host `api.Memory.Read` caller.

**Concrete failure (same precondition as the bug the commit fixed):** guest grows memory to 65536 pages
(`len == 2^32`), executes `i32.load16_u` at effective `offset = 0xFFFFFFFE`. `hasSize(0xFFFFFFFE, 2)` →
`2^32 <= 2^32` → true; then `m.Buffer[0xFFFFFFFE : 0xFFFFFFFE+2]` with `+2` wrapping to `0` →
`m.Buffer[4294967294:0]` → **Go runtime panic `slice bounds out of range`** instead of a clean
`ErrRuntimeOutOfBoundsMemoryAccess`. `Read(0xFFFFFFF8, 8)` panics identically. CONFIRMED (traced + the diff
shows the two siblings were left untouched). **Direction:** change both to the bounded-by-slice-header form
`m.Buffer[offset:]` (for `Read`, `m.Buffer[offset : offset+uint64(byteCount)]` computed in `uint64`), and add
a 4 GiB-memory top-of-address load test so the next carried fix can't regress it.

### C14 — [FORK] `hasImportDependentDataOffsets` lacks the global-index bounds guard — Low — PLAUSIBLE
**`internal/wasm/store.go:320` vs `:242-245`.** `validateData`'s resolver guards `globalIndex >= len(m.Globals)`;
the new function does `g := m.Globals[globalIndex]` directly. With reference-types enabled (the default),
`validateData` is skipped (`:432`), so this is the first code to dereference an offset-expr global. An
out-of-range index would **panic** rather than fail-closed — *if* reachable. `resolveConstExprGlobalType`
(`module.go:716`) validates const-expr global indices at compile time, so I could not construct a passing
binary that reaches it (hence PLAUSIBLE), but the code contradicts its own "be conservative on evaluation
errors" comment (`:327-329`). **Direction:** add the bounds guard and refuse the skip on out-of-range.

### C15 — [FORK] Import-dependence check refuses on *any* global, doc/name says "imported" — Low — CONFIRMED
**`internal/wasm/store.go:305-334`, `experimental/memory.go:59-61`.** The doc and function name say the skip is
refused when an offset "depends on an **imported** global," but the recording resolver sets `usesGlobal=true`
for any `global.get`, including module-local constant globals legal under `CoreFeaturesExtendedConst` whose
values *are* fixed by module identity. Safe-direction (over-conservative), but the name and doc misstate the
condition and extended-const users silently lose the optimization. **Direction:** fix the doc/name to "any
global," or genuinely distinguish imported from local.

### C16 — [FORK] Skip gate doesn't require the module to own the memory — Low — PLAUSIBLE
**`internal/wasm/store.go:283-288`.** The design binds the skip to module identity but not to memory
*ownership* (`mem.ownerModuleEngine == m.Engine`, the predicate used at `module_instance.go:158`). With a
same-binary instance importing an earlier instance's pre-applied memory, `skipCopy` can become true against an
imported buffer; if that shared buffer was mutated at data-segment offsets between the two instantiations, the
"fresh" view diverges from the non-optimized path. Pathological config, but free to close. **Direction:** add
`mem.ownerModuleEngine == m.Engine` to the gate.

### C17 — [FORK] Offset const-exprs evaluated twice on the skip path — Low — CONFIRMED
**`internal/wasm/store.go:285,293`.** With a pre-applied allocator, each active offset expr is evaluated once
in `hasImportDependentDataOffsets` and again in the main loop — doubling const-expr work on exactly the path
the feature exists to accelerate. Not a correctness bug. **Direction:** reuse the computed offset, or fold the
import-dependence test into the main loop.

### C18 — [FORK] `hostModuleBuilder.Compile` never sets `compiledStore` → typeIDs re-interned every time — Low — CONFIRMED
**`builder.go:327` vs `runtime.go:340-345`.** The cross-store fast-path check `code.compiledStore != r.store`
is always true for host modules (the field is left nil), so typeIDs are re-interned (store RLock +
allocations, `store.go:655-667`) on **every** instantiation of a compiled host module, including the
common same-runtime case the field was added to short-circuit. Two sources of truth for typeID ownership.
**Direction:** set `compiledStore: b.r.store` in `Compile`.

### C19 — [FORK] `WithCompilationWorkers` changes cancellation semantics of the same API call — Low — CONFIRMED
**`internal/engine/wazevo/engine.go:264-330`.** With `workers > 1`, `CompileModule` checks `ctx.Err()`
per-function; the default serial path ignores ctx entirely. Same call, different cancellation behavior gated
on an unrelated perf knob; `GetCompilationWorkers` is also silently ignored by the interpreter engine.
**Direction:** check ctx in the serial loop too; document engine scope.

### C20 — [UPSTREAM] `hostModuleBuilder.Compile` skips `failIfClosed` — Low — CONFIRMED
**`builder.go:319-345`.** Unlike `runtime.CompileModule` (`runtime.go:230`), it never checks the closed flag,
so compiling a host module against a closed runtime silently succeeds and registers code in an already-closed
engine that will never be freed. **Direction:** check the closed state in `Compile`.

### C21 — [UPSTREAM] `cache.Close` stops on the first engine error — Low — CONFIRMED
**`cache.go:77-86`.** Returns on the first engine whose `Close()` errs, leaking the others (interpreter +
compiler can coexist). `runtime.CloseWithExitCode` (`:400-407`) likewise drops the store-close error when the
engine-close error is non-nil. **Direction:** close all, join errors.

### C22 — [UPSTREAM] Allocator failure paths panic instead of erroring — Low — CONFIRMED
**`internal/wasm/memory.go:76-80` via `experimental/memory.go:11-43`.** `MemoryAllocator.Allocate` returning
nil, or the initial `Reallocate(minBytes)` returning nil/short (which `LinearMemory` docs *explicitly permit*
"if it fails to grow"), yields an undocumented panic inside `InstantiateModule` rather than an instantiation
error. Related: `LinearMemory.Free()` runs when the *owning* module closes with no guard for live importers —
with an mmap allocator, importer access is use-after-unmap (`module_instance.go:159-162`), undocumented.
**Direction:** turn allocation failure into an error; document the first-`Reallocate` and `Free` ordering
constraints.

### C23 — [UPSTREAM] Doc examples/statements that don't compile or misstate behavior — Low — CONFIRMED
Bundled: `WithWalltime`/`WithNanotime` examples pass a `context.Context`-taking func but the `sys.Walltime`/
`sys.Nanotime` types take none (`config.go:580-606`); `CloseWithExitCode` example calls the nonexistent
`InstantiateSnapshotPreview1` (`runtime.go:130-136`); `Memory.Read` cites `WithMemoryCapacityPages`, the real
API is `WithMemoryCapacityFromMax` (`api/wasm.go:645`); `WithCompilationCache` example uses an undefined `c`
and a no-arg `cache.Close()` (`config.go:120`); `api.CoreFeatures.IsEnabled` doc says "the feature (or group)
is enabled" but tests `f&feature != 0`, i.e. *any* bit (`api/features.go:157`); `GetSnapshotter` panics on a
nil interface with no comma-ok variant and undocumented panic (`experimental/checkpoint.go:31`); truncated
"return ENO[SYS]" sentence (`experimental/sys/fs.go:12`). **Direction:** fix each; add these files to the
doc-example compile check if one exists.

### C24 — [FORK] Dead CODEOWNERS and residual upstream references — Low — CONFIRMED
`.github/CODEOWNERS` → `@wazero/maintainers` (no such team in the fork's org) silently assigns no reviewers;
the README fork note is honest but its badge, `site/**`, and `install.sh` still advertise
`github.com/tetratelabs/wazero`. **Direction:** delete or repoint CODEOWNERS; leave marketing-site drift.

### C26 — [FORK] Cancellation-enabled loop bodies lose known-safe-bounds — Low (perf) — CONFIRMED
**`internal/engine/wazevo/frontend/lower.go:1366-1439`, `:171-182`** (commit `3bde8fa4`).

Without `ensureTermination`, a loop body inherits the predecessor's known-safe memory bounds (single-pred
`initializeCurrentBlockKnownBounds`), so redundant bounds checks inside the loop are elided. With the inline
termination check, the loop body becomes `contBlk` whose two predecessors (`loopHeader`, `slowBlk`) are never
finalized in `knownSafeBoundsAtTheEndOfBlocks`, so the bounds intersection is empty and **every** bounds check
is re-emitted inside cancellation-enabled loops; `contBlk` also accretes extra phi params. Correctness is
unaffected (strictly conservative), but this is a second-order perf cost stacked on top of the feature's
intended speedup, in exactly the hot loops it targets. CONFIRMED (traced). **Direction:** finalize the
header's bounds into `contBlk`, or mark the `loopHeader → contBlk` edge bound-preserving.

### B1 — [FORK] SSA load-CSE: invalidation is an opcode whitelist — Low — PLAUSIBLE (latent)
**`internal/engine/wazevo/ssa/pass_load_cse.go:48-77`** (commit `5c0c6e9c`). The pass was traced
hazard-by-hazard and is **correct today**: aliasing stores evict conservatively (different-root ⇒ delete;
same-root ⇒ exact signed-distance overlap), `memory.grow`/all memory-bulk ops/atomics/`Fence`/calls (incl. Go
trampolines via `CallIndirect`) clear the cache, the key includes opcode + result type so widths/extends never
cross-match, and partial stores never forward. The residual risk is structural: invalidation is a closed
whitelist, so a *future* SSA opcode that writes memory or returns control would silently miscompile.
`OpcodeTailCallReturnCall/Indirect` are already absent from the list — harmless only because the frontend
marks state unreachable after them. **Direction:** default to clearing on any `sideEffectStrict` opcode not
explicitly known-safe. **Test gaps:** the added test omits call/atomic/fence invalidation, partial-overlap
eviction, `Sload8` vs `Uload8` non-merging, and multi-block isolation.

---

## 4. Design tensions

**T1 — The pre-applied fast path's only safe input is a state wazero never exposes.** The correct image
(memory after `applyData`, before start) is a transient the host cannot easily obtain; the states it *can*
snapshot (post-start, post-execution) are wrong (C2/C5). The ID binding (`25ea61ec`) hardened *which module*
but left *which point in init* as prose. Alternative: refuse the skip when a start section exists, converting
the last doc-rule into an invariant and making the feature safe-by-construction for its actual workload.

**T2 — Correctness-critical compiler optimizations gated on non-local invariants, thin integration testing.**
`fd1cb8f3` (C1) shipped a real miscompile that unit tests missed; `5c0c6e9c` is correct but only because a
closed whitelist happens to be exhaustive (B1); `3bde8fa4` depends on a pointer staying valid for the
invocation. For a Wasm engine the real net is the differential/fuzz suite (interpreter vs compiler), and the
fork delta adds no coverage there. Alternative: run the spec + differential fuzz suite against each backend
commit and record it in the trail before relying on the fast paths.

**T3 — "Experimental" is carrying a semantics-changing knob with isolation-knob ceremony.**
`MemoryWithPreappliedData` can silently corrupt guest state (C2), yet is an implicitly-detected optional
interface with no example. The package's "defer safety to the caller" stance is fine for *isolation-preserving*
knobs (and isolation genuinely is never at risk here — image bytes come only from the host) but weak for a
*semantics-changing* one. Alternative: a louder, explicit opt-in (`UnsafePreappliedMemory(...)`) over silent
interface detection.

**T4 — The `offset > 0` idiom recurs across addressing-mode construction.** C1 is one instance; the
RegExtended fallthrough at `:398` shares it. The addend/offset machinery treats "no immediate slot" and
"immediate is zero" inconsistently across branches. Alternative: normalize so every branch that selects an
immediate-less amode routes a *nonzero* residual (either sign) through `addConstToReg64`, with one guard, not
four.

---

## 5. Expectation gaps (expected X, found Y)

- **Expected** `p + i*8 - 8` to load from `p + i*8 - 8`. **Found** it loads from `p + i*8` on arm64 (C1).
- **Expected** snapshotting a freshly-instantiated instance's memory to be a valid pre-applied image.
  **Found** it double-runs the start function (C2).
- **Expected** to compute the moduleID as `sha256(binary)` per the doc. **Found** the real ID hashes extra
  flags, so it never matches and the skip silently no-ops (C6).
- **Expected** the skip to refuse whenever it can't guarantee correctness (as it does for ID mismatch and
  globals). **Found** it doesn't refuse the start-function case, the likeliest real mistake (C2/C5).
- **Expected** `ModuleConfig` to be immutable and safe to fork/share. **Found** `WithEnv` forks alias and a
  shared config is mutated during instantiation (C3, C10).
- **Expected** an `ImportResolver` to be able to return any `api.Module`. **Found** returning a host module
  panics (C4).
- **Expected** a footgun-y experimental feature to ship with an example. **Found** none; source-only (C7).
- **Expected** CODEOWNERS to assign reviewers. **Found** it names a nonexistent team and assigns none (C24).

## 6. Open questions (need maintainer input)

1. **Intended capture point for pre-applied images** — "after data, before start" (making the doc's
   "previously initialized instance" example wrong), or "only modules with no start section"? Decides whether
   C2 is a doc fix or a code guard.
2. **Are start-section modules in scope** for the optimization, or is the target workload known start-free?
   Bounds C2's real blast radius.
3. **Is the differential/fuzz suite run against `fd1cb8f3` and `5c0c6e9c`?** C1 shows unit tests are not
   enough for the backend commits.
4. **Termination check scope** — reading only the *entry* module's `Closed` (not imported instances'): a
   deliberate match to prior trampoline behavior, or an unexamined carry-over? (No regression found; asking
   whether it's intended.)
5. **Provenance triage** — several High/Medium items (C3, C4, C9–C13) are inherited from upstream. Does the
   fork want to carry local fixes, or only patch fork-introduced regressions (C1, C2) and upstream the rest?
