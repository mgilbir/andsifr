# Codebase Audit — andsifr / upstream wazero — 2026-07-06

**Scope.** This report audits the **whole codebase including the inherited upstream `tetratelabs/wazero`
code** (the 2026-07-05 report covered only the fork delta). Findings here are overwhelmingly **[UPSTREAM]**
(present at fork base `9a9d5440`; the fork only renamed import paths in these files) unless tagged **[FORK]**.
IDs use a `U` prefix so a fixing agent never confuses them with the fork report's `C`-series.

**Method & caveat.** Upstream wazero is mature and continuously fuzzed (`internal/integration_test`,
`fuzz/`), so the bar for a "bug" is high and most obvious classes (LEB128 overflow, section over-read, numeric
spectests) are already handled — this report says so where true and spends effort only where something
genuinely diverges. Coverage was fanned out across subsystems in two waves: (1) decoder/validator, WASI,
sysfs/fd, interpreter numerics, amd64 + arm64 codegen, host-call/API, CLI/platform/filecache; (2)
tables/elements/reference-types runtime, shared-memory/threads/atomics, the experimental observability surface
(listeners, snapshotter, checkpoint, DWARF/stack traces), and machine-code instruction encoders. Each finding
was traced to file:line; the highest-severity ones (U1, U5, U16, U17) and every provenance claim were
re-verified by hand against the source (one agent's "fork-introduced" tag on U22 was corrected to UPSTREAM
after checking git).

---

## 1. Summary table

| ID  | Sev | Prov | Area | One-line issue | Location | Status |
|-----|-----|------|------|----------------|----------|--------|
| U1  | High | UPSTREAM | Decoder/validate | `try_table` catch-clause validation indexes the body by an attacker count → unrecovered panic (host DoS) from `CompileModule` | `internal/wasm/func_validation.go:597-599` | CONFIRMED |
| U5  | High | UPSTREAM | WASI fd table | `fd_renumber(fd, 0x7FFFFFFF)` grows the fd table to ~17 GB → fatal host OOM (guest-triggerable) | `internal/sys/fs.go:289-314`, `internal/descriptor/table.go:97-109` | CONFIRMED |
| U16 | High | UPSTREAM | amd64 codegen | `Icmp(0, Band(x,y), cond)` (const on left) folds to `TEST` but applies the condition unswapped → every ordering compare inverted | `internal/engine/wazevo/backend/isa/amd64/machine.go:1685-1715` | CONFIRMED |
| U17 | High | UPSTREAM | arm64 codegen | `Icmp(Band(x,y), 0)` folds `Band`→`ANDS` (forces C=0) but keeps unsigned conditions that read C → unsigned compare-vs-0 always constant | `internal/engine/wazevo/backend/isa/arm64/lower_instr.go:126-149` | CONFIRMED |
| U6  | Med | UPSTREAM | WASI FS | Guest-created relative symlink escapes a writable OS-backed preopen (no `openat2`/`RESOLVE_BENEATH`) | `internal/sysfs/dirfs.go:95-137` | CONFIRMED |
| U7  | Med | UPSTREAM | CLI | Invalid `--mount` (non-directory) prints an error but does not abort; module runs with a file mounted as a dir | `cmd/wazero/wazero.go:416-418` | CONFIRMED |
| U8  | Med | UPSTREAM | CLI | Invalid `--listen` prints an error but does not abort, and silently drops earlier valid listeners | `cmd/wazero/wazero.go:435-453` | CONFIRMED |
| U15 | Med | UPSTREAM | emscripten | Zero-param `invoke_` import panics the exporter builder (outside any wasm frame → unrecovered host DoS) | `internal/emscripten/emscripten.go:72-76` | CONFIRMED |
| U19 | Med | UPSTREAM | Threads | `memory.atomic.wait` timeout races `notify`: a notified waiter can return "timed out" → lost wakeup / notify overcount | `internal/wasm/memory.go:405-475` | CONFIRMED |
| U23 | Med | UPSTREAM | Types | Rec-group structural type-ID key reads `tid=0` for a forward concrete-ref → possible `call_indirect` type confusion | `internal/wasm/store.go:672-729` | PLAUSIBLE |
| U26 | Med | UPSTREAM | Observability | `MultiFunctionListenerFactory` stack iterator reports the bottom frame's function for *every* frame under wazevo | `experimental/listener.go:202-222` | CONFIRMED |
| U20 | Low | UPSTREAM | Threads | wazevo owner-shared-memory `Grow` writes the length non-atomically while bounds checks read it atomically (torn read) | `internal/engine/wazevo/module_engine.go:258-269` | CONFIRMED |
| U21 | Low | UPSTREAM | Tables | Passive **externref** element segment left as a nil `ElementInstance` → `table.init` traps on a legal null-copy | `internal/wasm/store.go:183` | CONFIRMED |
| U22 | Low | UPSTREAM | Tables | Active **externref** element segment ignores its init const-expr and writes null | `internal/wasm/store.go:221-224` | CONFIRMED |
| U24 | Low | UPSTREAM | Threads | `waiters` sync.Map entries are never pruned → slow unbounded growth across distinct wait addresses | `internal/wasm/memory.go:441-451` | PLAUSIBLE |
| U25 | Low | UPSTREAM | arm64 encoder | `SSHLL`/`USHLL` shift-immediate formula is correct only at shift 0 (latent; all call sites pass 0) | `internal/engine/wazevo/backend/isa/arm64/instr_encoding.go:1881-1922` | PLAUSIBLE |
| U27 | Low | UPSTREAM | Observability | wazevo `SourceOffsetForPC` derefs a nil `compiledModule` (unknown/stale PC) → panic while formatting a trace | `internal/engine/wazevo/call_engine.go:874-879` | PLAUSIBLE |
| U28 | Low | UPSTREAM | DWARF | Inlined-frame formatter guards `fileIndex` upper bound only; a negative index panics stack-trace formatting | `internal/wasmdebug/dwarf.go:191-198` | PLAUSIBLE |
| U29 | Low | UPSTREAM | wazevo | `GetCompilationWorkers` clamps the minimum but not the maximum → huge value spawns that many goroutines | `experimental/compilationworkers.go:16-19` | CONFIRMED |
| U2  | Low | UPSTREAM | Validation | Const-expr forward-ref check compares the item index against the section-ID constant (`sectionIdx == SectionIDGlobal`) | `internal/wasm/module.go:746` | CONFIRMED |
| U3  | Low | FORK | WASI poll | `poll_oneoff` with `clock + non-pollable fd` returns before the deadline (no wait in the deferred path) | `imports/wasi_snapshot_preview1/poll.go:164-218` | CONFIRMED |
| U4  | Low | UPSTREAM | WASI poll | Fast path `Nanosleep(timeout)` even when an fd event is already ready | `imports/wasi_snapshot_preview1/poll.go:166-174` | CONFIRMED |
| U9  | Low | UPSTREAM | CLI | `--mount=:ro` silently mounts the current working directory at guest root | `cmd/wazero/wazero.go:385-411` | CONFIRMED |
| U10 | Low | UPSTREAM | CLI | Lone `--` separator leaks into guest argv | `cmd/wazero/wazero.go:244-250` | CONFIRMED |
| U11 | Low | FORK | CLI docs | README install command points at `tetratelabs/wazero`; prose contradicts subcommand UI; flags undocumented | `cmd/wazero/README.md` | CONFIRMED |
| U12 | Low | UPSTREAM | Platform | Windows `MprotectCodeSegment` races on a package-global `old` out-param | `internal/platform/mmap_windows.go:26-30` | PLAUSIBLE |
| U13 | Low | UPSTREAM | Platform | amd64 ABM/LZCNT is inferred from BMI1+BMI2+POPCNT, not detected; a miss silently runs BSR | `internal/platform/cpuid_amd64.go:18-20` | PLAUSIBLE |
| U14 | Low | UPSTREAM | Interpreter | `sqrt` bypasses NaN canonicalization (spec-correct only because real HW sqrt yields canonical NaN) | `internal/engine/interpreter/interpreter.go:1564-1573` | PLAUSIBLE |
| U18 | Low | UPSTREAM | amd64 codegen | Two-shifted-register address fold shifts a value in place with no regalloc redefinition model (latent clobber) | `internal/engine/wazevo/backend/isa/amd64/lower_mem.go:102-108` | PLAUSIBLE |

**Counts:** 29 findings — High 4 · Medium 7 · Low 18 (9 PLAUSIBLE). Provenance: 27 UPSTREAM, 2 FORK (U3 poll
timing, U11 CLI-README drift — both minor). The two most serious are independent **codegen miscompilations** of the same optimization
(`Icmp(Band, 0)` → single flag-setting instruction) in **both** backends: U16 (amd64) and U17 (arm64). Both
survive the spectest/fuzz corpus because the trigger (a single-use `and` compared unsigned/ordered against a
constant 0, feeding a branch) is a shape most producers canonicalize away — but both are wrong for valid wasm.

_(more rows below in §3; the amd64, arm64/frontend, and host/API subsystem audits have all reported.)_

---

## 2. System map (whole system)

**Entry points.** `wazero.NewRuntime` → `CompileModule` (decode → validate → assign SHA-256 ID → engine
compile) → `InstantiateModule` → guest exports / start / WASI `_start`. Two engines: the **wazevo** optimizing
compiler (arm64 + amd64, SSA-based) and the **interpreter** (portable fallback). Host functionality is exposed
as host modules (`HostModuleBuilder`, WASI, emscripten, assemblyscript) whose Go functions are adapted by
reflection (`internal/wasm/gofunc.go`) or by a fast typed ABI. The CLI (`cmd/wazero`) wraps the runtime with
`--mount`/`--env`/`--listen`/cache flags. Untrusted input crosses two boundaries: the **`.wasm` binary**
(decoder + validator, `internal/wasm/binary` + `func_validation.go`) and **guest↔host memory** (WASI/host
funcs read guest linear memory by offset+len).

**Trust boundaries & invariants.**
- *Binary boundary:* every vector count/index from the binary must be validated (or bounds-checked at use)
  before it drives allocation or indexing. LEB128 decoders are length- and overflow-bounded; section sizes
  are reconciled against bytes consumed (`decoder.go:155-158`). The one place this invariant breaks is the
  exception-handling `try_table` validator (U1).
- *Validation-before-execution:* `Module.Validate` runs before instantiation; runtime evaluators
  (`evaluateConstExprInModuleInstance`, memory access) then trust that validation. There is **no `recover`**
  around decode/validate in `CompileModule` (only around runtime execution), so any panic in the
  decoder/validator crashes the host (amplifies U1).
- *Sandbox boundary:* WASI path resolution applies `path.Clean` + `fs.ValidPath` (rejects absolute/`..`
  escapes) and delegates symlink resolution to the OS `openat`; the fd table (`internal/sys/fs.go`,
  `internal/descriptor`) rejects preopen renumber/close and negative fds. This layer is stock upstream and
  audited clean in this pass (no traversal/fd-confusion found).

---

## 3. Findings

### U1 — [UPSTREAM] `try_table` catch-clause validation panics on a crafted body (host DoS) — High — CONFIRMED
**`internal/wasm/func_validation.go:597-599`** (introduced upstream by `bfb20e0b`, "exception handling spec
(#2489)"; present at fork base).

**Should:** every read of `body[pc]` during validation of untrusted code must be bounds-checked; a malformed
body must produce a validation *error*, never a panic.

**Reality:** the catch-clause loop is bounded by `catchCount`, an attacker-controlled LEB128 vector length
read from the code body (`:590`), and indexes `body[pc]` (`:599`) after `pc++` with no `pc < len(body)` guard:
```go
for i := uint32(0); i < catchCount; i++ {
    pc++
    catchKind := body[pc]   // unchecked; pc driven by attacker's catchCount
```
When a crafted clause consumes the final body byte and `catchCount` exceeds the real clause count, the next
iteration indexes `body[len(body)]` → `panic: runtime error: index out of range`.

**Concrete failure:** a code-section body ending in `0x0B` (so `decodeCode` accepts it) containing
`try_table void, catchCount=2, catch_all, label=0x0B`. Fed to `runtime.CompileModule`, it reaches
`internal.Validate` → `validateFunction`, which has **no `recover`** on the compile/validate path
(`runtime.go:234-238`), so the host process/goroutine crashes. _(agent-reproduced: panicked at
`func_validation.go:599`, "index out of range [29] with length 29".)_ Gated behind
`experimental.CoreFeaturesExceptionHandling` (off by default), so the exposure is any host that enables
exception handling to run untrusted modules.

**Direction:** guard every `body[pc]`/`body[pc:]` read in the try_table catch loop with
`if pc >= uint64(len(body)) { return errUnexpectedEnd }` (the single-immediate direct reads elsewhere in this
file are saved by the trailing `OpcodeEnd`; only this attacker-count-driven loop is exploitable). Consider a
defensive `recover` around decode/validate as defense-in-depth for a boundary that parses fully-untrusted
input.

### U16 — [UPSTREAM] amd64: `Icmp(0, Band(x,y), cond)` fold inverts ordering comparisons — High — CONFIRMED
**`internal/engine/wazevo/backend/isa/amd64/machine.go:1685-1715`** (from upstream PR #2073).

**Should:** the fold of `Icmp(Band(x,y), 0)` to a single `TEST x,y` is valid only when the constant `0` is the
**right** operand, because `TEST` sets SF/ZF/PF from `x&y` and clears CF/OF — i.e. it produces the flags of
`(x&y) CMP 0`, with the band result as the *left* comparison operand.

**Reality:** the function also matches the commuted form `Icmp(0, Band(x,y), c)` (`:1688-1693`, the
`x.Instr.Constant()…==0` branch), emits the same `TEST`, and the caller applies `condFromSSAIntCmpCond(c)`
**unchanged**. But here the IR means `0 c (x&y)`, whose correct flags come from `0 - (x&y)` — the opposite
operand order. Every ordering condition (`lt/gt/le/ge`, signed or unsigned) is therefore inverted; `eq`/`ne`
are symmetric and stay correct (which is why the corpus never caught it).

**Concrete failure:** `(i32.const 0) (i32.and a b) i32.lt_s` (`Icmp(0, Band(a,b), SignedLessThan)`) lowers to
`test a,b; jl …`, computing `(a&b) <s 0` instead of `0 <s (a&b)`. _(agent-traced with `go run` reproducers:
`0 <s (a&b)` with a=b=1 returned 200, correct 100; with a=b=0xffffffff returned 100, correct 200;
`0 >=u (a&b)` with a=b=1 returned 100, correct 200.)_ Affects all three callers — `brz`/`brnz`,
`lowerExitIfTrueWithCode`, and `…Shared` — so a conditional **trap** whose guard is `0 <ord> (x&y)` also traps
in the wrong direction. **Direction:** drop the const-on-left branch (restrict to const-on-right, matching PR
intent), or emit an operand-swapped condition, or restrict the fold to `eq`/`ne`.

### U17 — [UPSTREAM] arm64: `Icmp(Band(x,y), 0)` fold uses `ANDS`, breaking unsigned compares — High — CONFIRMED
**`internal/engine/wazevo/backend/isa/arm64/lower_instr.go:126-149`**, reached from `LowerConditionalBranch`
(`:85-95`). Byte-identical to upstream v1.10.1 — latent upstream bug.

**Should:** a branch on `Icmp <cond> (Band X Y), 0` needs flags equivalent to `SUBS rn,#0`, which sets **C=1**.

**Reality:** `tryLowerBandToFlag` lowers the `Band` to a flag-setting `ANDS` (`aluOpAnds`, `:132/:142`), and the
caller computes `cc` from the icmp condition with **no restriction to eq/ne** (`:88`). On AArch64 `ANDS` forces
`C=0, V=0`. The unsigned conditions all read C, so after `ANDS` they become constants: `hi`(C&&!Z)→false,
`hs`(C)→false, `lo`(!C)→true, `ls`(!C||Z)→true.

**Concrete failure:** `if (i32.gt_u (i32.and a b) (i32.const 0))` emits `ands wzr, a, b; b.ls <else>`; `b.ls` is
always taken (C==0), so the `then` arm is dead **even when `a&b != 0`**. Correct lowering `subs wzr, w, #0;
b.ls` sets C=1, making `ls` mean exactly `a&b == 0`. _(agent-verified via `LowerConditionalBranch`.)_ Miscompiles
`gt_u/ge_u/lt_u/le_u (i32|i64.and a b) 0` feeding an `if`/`br_if` (both `Brz` and `Brnz`). Signed and eq/ne are
unaffected (they don't read C); `lowerSelect` uses `SUBS` directly and is fine; the trap-check callers use only
eq/ne conditions, so no live trap site is hit. **Direction:** fire `tryLowerBandToFlag` only for `eq`/`ne`,
else fall back to `SUBS`.

### U5 — [UPSTREAM] `fd_renumber` to a huge target fd OOMs the host — High — CONFIRMED
**`internal/sys/fs.go:289-314` (`Renumber`) → `internal/descriptor/table.go:97-109` (`InsertAt`).**

**Should:** a guest-supplied target fd must be bounded (like an OS `RLIMIT_NOFILE`) before it drives allocation.

**Reality:** `Renumber` validates only `to < 0` (`fs.go:291`); any non-negative `to` reaches `InsertAt`, which
grows the backing arrays to physically contain index `to` with no upper bound:
```go
index := uint(key) / 64
if diff := int(index) - len(t.masks) + 1; diff > 0 { t.grow(diff) }
...
t.items[key] = item   // requires len(items) > key
```
`fdRenumberFn` takes `to := int32(params[1])` straight from guest memory.

**Concrete failure:** mount any writable preopen; guest does `path_open(preopen,"f") → fd`, then
`fd_renumber(fd, 0x7FFFFFFF)`. `InsertAt` computes `index = 2147483647/64 ≈ 33.5 M`, grows `masks` (~268 MB)
and `items` (~2.1 billion `*FileEntry` ≈ **17 GB**) → Go's allocator raises a **fatal**
`runtime: out of memory` (not a catchable panic) → the whole host process dies. A single guest call takes down
a multi-tenant embedder. _(Mechanism traced; `Test_sizeOfTable` demonstrates `InsertAt(_,257)` → 5 masks.)_
**Direction:** bound `to` in `Renumber` (reject beyond `openedFiles.Len() + smallDelta`, or a hard cap
mirroring `RLIMIT_NOFILE`).

### U6 — [UPSTREAM] Guest-created relative symlink escapes a writable OS-backed preopen — Medium — CONFIRMED
**`internal/sysfs/dirfs.go:95-137`, `internal/sysfs/open_file_unix.go:14-20`.**

`dirFS.join` concatenates strings with no `..`/symlink containment (acknowledged TODO at `dirfs.go:134-135`),
and `openFile` uses `os.OpenFile`, which resolves symlinks and `..` against the *real* directory — there is no
`openat2`/`RESOLVE_BENEATH`. The `path.Clean`+`fs.ValidPath` gate only sanitizes the guest-supplied *literal*
path, not an on-disk symlink target.

**Concrete failure (writable OS-backed preopen):** guest calls
`path_symlink(oldpath="../../../../etc", newpath="esc")` — `dirFS.Symlink` rejects only *absolute* oldpaths
(`dirfs.go:99`), so the relative one is created on the host. Then `path_open(preopen, "esc/passwd")`:
`path.Clean("esc/passwd")` passes `fs.ValidPath`, and `O_NOFOLLOW` only guards the final component, so the
kernel follows the intermediate `esc` symlink → opens `/etc/passwd` outside the root. CONFIRMED. This is a
**documented, well-known DirFS limitation**, not novel, and is mitigated for the safe configurations: `ReadFS`
blocks `Symlink` (EROFS), and `AdaptFS` (an `fs.FS`-backed mount) is fully contained because `fs.Open` enforces
`fs.ValidPath` and `Symlink` returns ENOSYS. Reported because the exposure (writable `os.DirFS` mount + a guest
that can create symlinks) is exactly the CLI's `--mount=host:guest` default and is easy to reach.
**Direction:** use `openat2(RESOLVE_BENEATH)` on Linux (fall back to lexical resolution elsewhere), or document
loudly that writable OS mounts are not a security boundary against a hostile guest.

### U7 — [UPSTREAM] Invalid `--mount` of a non-directory is reported but not aborted — Medium — CONFIRMED
**`cmd/wazero/wazero.go:416-418`.** Every other mount-validation branch `return`s `1`; the non-directory
branch only prints and falls through:
```go
} else if !stat.IsDir() {
    fmt.Fprintf(stdErr, "invalid mount: path %q is not a directory\n", dir)
}   // missing: return 1, rootPath, config
```
It then builds `sysfs.DirFS(dir)` on a *file* and runs the module anyway.
**Concrete failure:** `wazero run --mount=/etc/hosts:/x app.wasm` prints "invalid mount: … is not a directory"
yet still instantiates and runs the guest, exiting with the module's own code (often 0). The user believes the
mount failed; the program ran. No test covers this branch. CONFIRMED. **Direction:** add the missing
`return 1, rootPath, config`.

### U8 — [UPSTREAM] Invalid `--listen` is reported but not aborted, and drops earlier listeners — Medium — CONFIRMED
**`cmd/wazero/wazero.go:435-453`, caller `:317`.** `validateListens` never assigns a non-zero `rc`; on a bad
entry it prints and `return rc, config` with `rc == 0`, so the caller's `if rc != 0 { return rc }` never fires
and execution continues with a `nil`/partial socket config.
**Concrete failures:** `--listen=badvalue` → prints "invalid listen", then runs the module with no socket
(exit 0). `--listen=:8080 --listen=host:notaport` → the second (invalid) entry returns early carrying only the
*partial* config, **silently discarding the valid `:8080` listener**. No listen tests exist. CONFIRMED.
**Direction:** set `rc = 1` before each early return, mirroring `validateMounts`.

### U15 — [UPSTREAM] Zero-parameter `invoke_` import panics the emscripten exporter — Medium — CONFIRMED
**`internal/emscripten/emscripten.go:72-76`, reachability `imports/emscripten/emscripten.go:103-121`.**

`NewInvokeFunc` does `paramNames := make([]string, len(params)); paramNames[0] = "index"` with no guard.
`NewFunctionExporterForModule`/`InstantiateForModule` iterates the guest's imports and calls `NewInvokeFunc`
for **any** import in module `"env"` whose name merely `HasPrefix "invoke_"` — import names and signatures are
fully guest-controlled, and a zero-param import is valid wasm that passes `CompileModule`.

**Concrete failure:** a guest declaring `(import "env" "invoke_" (func))` (zero params) makes
`emscripten.NewFunctionExporterForModule(guest)` execute `paramNames[0] = "index"` on a length-0 slice →
`panic: index out of range [0] with length 0`. This runs during exporter construction — **outside any wasm
call frame** — so the engine's `recoverOnCall` does not catch it; it propagates as an unrecovered panic that
crashes the embedder. _(agent-verified with a unit test.)_ Exposure: embedders using emscripten support with
untrusted modules. **Direction:** reject (or skip with an error) an `invoke_` import with `len(params) == 0`
up front — `InvokeFunc.Call` also assumes `stack[0]` is the table index, so a zero-param invoke is meaningless.

### U19 — [UPSTREAM] `memory.atomic.wait` timeout races `notify` → lost wakeup — Medium — CONFIRMED
**`internal/wasm/memory.go:405-439` (`wait`), `:454-475` (`Notify`)** (upstream `6b21510c`, threads proposal).

**Should:** a waiter that `notify` selects and counts must return `0` ("notified"); the notify count must equal
the number of waiters that actually observe a wakeup.

**Reality:** on timeout the waiter runs `select { case <-ready: return 0; case <-time.After(...): remove; return 2 }`.
`Notify` removes the waiter's list element, `close(ready)`, and increments `res` **before** the waiter commits a
result. Go `select` chooses uniformly among ready cases, so in the overlap window a just-notified waiter can take
the `time.After` branch and return `2` (timed out) even though `Notify` already counted it.

**Concrete failure:** two waiters W1,W2 parked on one offset with finite timeouts; notifier `Notify(off, 1)`
removes+closes W1's channel and returns 1, but W1's timeout fires concurrently and its `select` picks the timeout
case → W1 returns `2`. Net: notify reported "1 woken" yet **no** waiter progressed (W1 thinks it timed out, W2
still parked) — the notification is lost. In a guest lock-handoff protocol ("ownership passes to the woken
waiter"), ownership is handed to a thread that believes it timed out → deadlock or double-acquire. No test covers
this race. **Direction:** on the timeout branch, re-check the channel (`select { case <-ready: return 0; default: }`)
before returning `2`, so a waiter `Notify` already consumed reports notified — matching the `x/sync/semaphore`
pattern the file cites.

### U23 — [UPSTREAM] Rec-group structural type-ID key can read an unassigned `tid=0` — Medium — PLAUSIBLE
**`internal/wasm/store.go:672-729`.** `structuralValueTypeName` emits `tid = typeIDs[idx]` for a concrete ref
`(ref $q)`, but `GetFunctionTypeIDs` fills `ret` in order, so a forward reference to a *later* type in a
mutually-recursive rec group reads `typeIDs[q] == 0` (not yet assigned) — indistinguishable from a genuine
type-ID 0. Two structurally-different recursive types could then hash to the same key and share one
`FunctionTypeID`, which is exactly what `call_indirect` compares at runtime. If reachable, a `call_indirect`
could accept a wrong-typed funcref → call a function under the wrong signature → **type confusion / memory
unsafety** (sandbox-escape class). PLAUSIBLE only: I could not complete the trace into the `call_indirect`
codegen (declared out of scope for the tables audit), and it requires the GC/typed-function-references feature
with a mutually-recursive rec group. **Direction:** verify whether a forward concrete-ref in a rec group can
reach `structuralValueTypeName` with `tid==0`; if so, key on the rec-group-relative index (already partially done
via the `|rec%d/%d` suffix) rather than the global `typeIDs` slot, or assign IDs before hashing. This one is
worth a focused follow-up given the severity if confirmed.

### U2 — [UPSTREAM] Const-expr forward-reference check uses the wrong operand — Low — CONFIRMED
**`internal/wasm/module.go:746`.** `if sectionIdx == Index(SectionIDGlobal) && idx >= sectionIdx` compares the
*item index being validated* against the section-ID constant (`SectionIDGlobal` == 6); the comment ("Check
that the given global has been initialized") intends `sectionID == SectionIDGlobal`. As written the
self/forward-reference restriction fires only when the item index happens to equal 6. Net effect is nearly
inert (the global section resolves inits with an imported-globals-only resolver that rejects defined-global
references earlier), but under `CoreFeaturesExtendedConst` an **element** segment at index 6 whose init does
`global.get` of a defined-global index ≥6 is spuriously rejected (spec-conformance false-positive; no
memory-safety impact). **Direction:** change to `sectionID == SectionIDGlobal`; if the ExtendedConst
defined-global relaxation is meant to work for the global section too, reconcile `validateGlobals` (and note
`GlobalInstance.initialize` would index `importedGlobals` unchecked if that path became reachable).

### U3 — [FORK] `poll_oneoff` returns before the clock deadline for clock + non-pollable fd — Low — CONFIRMED
**`imports/wasi_snapshot_preview1/poll.go:164-218`** (commit `772f1240`, #2481). The clock timeout is observed
only as a side effect of a deferred fd's blocking `Poll()`; the deferred path has no `Nanosleep`. With
subscriptions `[clock(relative T), fd_read(non-pollable fd)]` (e.g. a regular file on a virtual `fs.FS` mount,
whose `Poll` returns `ENOSYS`), the deferred loop writes `ErrnoNotsup` and `continue`s without waiting, so
`poll_oneoff` returns immediately though `T` has not elapsed. Net improvement over pre-#2481 (which dropped
non-stdin fds), but a residual correctness gap. **Direction:** if a clock subscription is present and no
deferred fd actually blocks, `Nanosleep` the remaining budget before returning.

### U4 — [UPSTREAM] `poll_oneoff` fast path sleeps the full timeout even when an fd is ready — Low — CONFIRMED
**`imports/wasi_snapshot_preview1/poll.go:166-174`.** When every subscription is acked in the main loop (e.g.
`[clock(T), non-blocking-ready fd_read]`), the code `Nanosleep(T)` before returning despite a ready fd event;
POSIX `poll` returns immediately. Latency-only; unchanged by the fork. **Direction:** skip the sleep when
`nevents` already includes a non-clock event.

### U9 — [UPSTREAM] `--mount=:ro` silently mounts the current working directory — Low — CONFIRMED
**`cmd/wazero/wazero.go:385-411`.** The empty-string guard runs on the original argument; `--mount=:ro`
(length 3) passes it, is trimmed to `""` (readOnly=true), and `filepath.Abs("")` resolves to the cwd, which
stats as a directory and is mounted read-only at guest root. `--mount=` alone is correctly rejected;
`--mount=:ro` exposes the cwd to the guest with no path given. **Direction:** reject an empty host path after
stripping the `:ro`/`:rw` suffix.

### U10 — [UPSTREAM] Lone `--` separator leaks into guest argv — Low — CONFIRMED
**`cmd/wazero/wazero.go:244-250`.** The `--` is stripped only when `len(wasmArgs) > 1`, so
`wazero run app.wasm --` passes `"--"` through as `argv[1]` to the guest. **Direction:** guard
`len(wasmArgs) > 0 && wasmArgs[0] == "--"`.

### U11 — [FORK] CLI README drift — Low — CONFIRMED
**`cmd/wazero/README.md`.** The install command `go install github.com/tetratelabs/wazero/cmd/wazero@latest`
installs upstream, not this fork (`go.mod` module is `github.com/mgilbir/andsifr`); the prose "accepts a single
argument" contradicts the actual `run`/`compile`/`version` subcommand UI; and none of the security-relevant
flags (`--mount`, `--listen`, `--env`, `--timeout`, `--hostlogging`, `--cachedir`, `--interpreter`) or the
`compile` subcommand are documented. Tagged FORK because the rename is what made the install line wrong.
**Direction:** update the install path and document the flags.

### U12 — [UPSTREAM] Windows `MprotectCodeSegment` races on a package-global out-param — Low — PLAUSIBLE
**`internal/platform/mmap_windows.go:26-30`.** A package-level `var old` is passed as the `lpflOldProtect`
out-parameter of every `VirtualProtect`; concurrent code-segment protection (e.g. `--workers>1`, concurrent
`CompileModule`, or cache deserialization at `engine_cache.go:289`) races on it. The written value is never
read, so the effect is benign, but it is a genuine data race the detector flags. **Direction:** make `old` a
local.

### U13 — [UPSTREAM] amd64 ABM/LZCNT is inferred, not detected — Low — PLAUSIBLE
**`internal/platform/cpuid_amd64.go:18-20`.** `CpuFeatureAmd64ABM` (gates LZCNT emission) is set from
`BMI1 && BMI2 && POPCNT` because `x/sys/cpu` doesn't expose ABM/LZCNT. On a CPU with BMI1+BMI2+POPCNT but no
LZCNT, the `F3 0F BD` encoding silently executes as `BSR` (wrong result, no fault) rather than trapping. The
inline comment argues this can't happen on real Intel/AMD parts (true in practice), so it is effectively sound
— but a heuristic, and a miss fails silently. **Direction:** note the assumption; there is no clean detection
via the current dependency.

### U14 — [UPSTREAM] Interpreter `sqrt` bypasses NaN canonicalization — Low — PLAUSIBLE
**`internal/engine/interpreter/interpreter.go:1564-1573`.** `operationKindSqrt` calls `math.Sqrt` directly
rather than routing through `returnF32/F64UniOp` for canonicalization. On amd64/arm64 (and every arch where Go
intrinsifies `math.Sqrt` to a hardware instruction) `sqrt(negative)` yields a canonical NaN, so it is
spec-correct in practice; only a hypothetical software-`math.Sqrt` platform would return a non-canonical NaN
for a non-NaN input. Not a bug on any platform wazero realistically runs on. **Direction:** route through the
canonicalizing helper for defensiveness.

### U18 — [UPSTREAM] amd64 two-shifted-register address fold clobbers a live value — Low — PLAUSIBLE
**`internal/engine/wazevo/backend/isa/amd64/lower_mem.go:102-108`.** When both addends of an address `Iadd`
are constant left-shifts `(a<<s1)+(b<<s2)`, the code emits `shl $s1, a.reg` **in place** on the SSA value's own
register (no `copyToTmp`); `shiftR` is `defKindNone` in the regalloc tables (`instr.go:2347`), so the allocator
does not model this as a redefinition of `a`. If `a` is live afterward its register is silently corrupted. No
wasm input reaching this branch was found — normal accesses always have `memBase` (shift 0) as one addend, so
`memOpSetup` never hits the two-non-zero-shift path — hence PLAUSIBLE/latent, not confirmed. **Direction:**
`copyToTmp` before the in-place shift, or mark it a redefinition.

### U20 — [UPSTREAM] wazevo owner-shared-memory `Grow` writes the length non-atomically — Low — CONFIRMED
**`internal/engine/wazevo/module_engine.go:258-269` (`putLocalMemory`) vs generated read at
`internal/engine/wazevo/frontend/lower.go:4575`.** For a shared memory the compiler deliberately reads the
opaque length field with `AsAtomicLoad` in every bounds check, but `putLocalMemory` (reached from a shared
`memory.grow`) writes that same 8-byte field with `binary.LittleEndian.PutUint64` — a non-atomic byte-by-byte
store, under only `m.Mux` while guest threads take no lock. A thread growing the memory can produce a **torn**
length read in another thread's bounds check (page-aligned lengths make a torn-larger value like
`0x0001_0000`+`0x0100_0000`→`0x0101_0000` reachable), transiently accepting an out-of-bounds access or rejecting
a valid one (spec violation). **Not** host-unsafe on this path because the backing `[]byte` is pre-reserved at
`maxBytes` and never moves, so the access still lands in the mmap'd region; the imported-shared path is already
correct (atomic store of the slice-header Len). The race detector can't see the JIT reader. **Direction:** store
the opaque length with `atomic.StoreUint64` to match the atomic reader.

### U21 — [UPSTREAM] Passive externref element segment traps `table.init` on a legal null-copy — Low — CONFIRMED
**`internal/wasm/store.go:183`.** `buildElementInstances` materializes an `ElementInstance` only for
`RefTypeFuncref.Kind() && ElementModePassive`; a passive **externref** segment is left as `nil`
(`ElementInstances[i]` len 0). At runtime both engines then trap on any nonzero `table.init` from it
(interpreter `interpreter.go:1948`, wazevo `frontend/lower.go:855` bounds check against len 0).
**Concrete failure:** `(elem externref (ref.null extern) (ref.null extern))` passive + `(table 4 externref)`;
`table.init 0 (i32.const 0) (i32.const 0) (i32.const 2)` copies two nulls (legal wasm) but raises
`ErrRuntimeInvalidTableAccess`. Reachable with pure wasm (no host externref needed). **Direction:** key the
materialization on `elm.Type.IsRef()` (funcref *or* externref), not just the funcref kind.

### U22 — [UPSTREAM] Active externref element segment ignores its init expression — Low — CONFIRMED
**`internal/wasm/store.go:221-224`.** For an externref table, `applyElements` hard-writes `Reference(0)` for
each entry, ignoring `elem.Init`; the funcref branch (`:226-228`) correctly evaluates the const-expr. Since the
reference-types change made `ElementSegment.Init` a `[]ConstantExpression`, an externref segment can now carry a
non-null value (e.g. `global.get` of an imported immutable externref global), which is validated
(`table.go:143-179`) but then discarded → `table[i]` is null instead of the host reference. Correctness/data-loss,
not memory-unsafe, and narrow (wazero's host externref support is limited — `table.go:25-26` calls externref "not
currently supported", so injecting a non-null host externref is itself uncommon). **Direction:** evaluate
`elem.Init` for externref tables too, mirroring the funcref branch.

### U24 — [UPSTREAM] `waiters` map entries are never pruned — Low — PLAUSIBLE
**`internal/wasm/memory.go:441-451`.** `getWaiters` does `LoadOrStore` into the `m.waiters` sync.Map and nothing
ever `Delete`s. A `wait` whose value doesn't match still creates a permanent empty `waiters{}`; after all
waiters at an offset drain, the entry persists. A long-running guest that waits/notifies across many distinct
addresses accumulates one struct per address forever — a slow unbounded leak, not a correctness bug.
**Direction:** prune empty entries under `w.mux`, or document the growth.

### U25 — [UPSTREAM] arm64 `SSHLL`/`USHLL` shift-immediate formula is correct only at shift 0 — Low — PLAUSIBLE
**`internal/engine/wazevo/backend/isa/arm64/instr_encoding.go:1881-1922`.** `encodeVecShiftImm` uses the
right-shift `immb = esize − (amount & …)` formula for the left-shift ops `vecOpSshll`/`vecOpUshll`; the correct
left-shift field is `esize + shift`. The two coincide only at `shift == 0`, which every current call site passes
(`lower_instr.go:451-452, 582-598`), so the emitted encoding is correct today (and the `amount==0` field overflow
happens to OR into the identical `immh` LSB and still yields the right value). A future lowering that emits
`SSHLL #N` with `N>0` would silently encode a shift by `esize−N`. Encoders were otherwise verified sound
(bitmask-immediate brute-forced against the ARM reference decoder, branch-range enforcement, ModRM/SIB/REX all
correct). **Direction:** use `esize + shift` for the left-shift ops, or assert `shift == 0` at the call.

### U26 — [UPSTREAM] `MultiFunctionListenerFactory` reports the wrong function for every frame under wazevo — Medium — CONFIRMED
**`experimental/listener.go:202-222`.** The multiplexer's `stackIterator.Next` eagerly drains the base iterator
into buffers so each wrapped listener can re-walk the stack: `si.fns = append(si.fns, si.base.Function())`. But
the wazevo engine's `StackIterator.Function()` returns the iterator **itself** (`call_engine.go:865-867`:
`return si`), and its `Definition()` returns `si.currentDef` which `Next()` overwrites every step. So `si.fns`
ends up holding N copies of the *same* pointer, whose `currentDef` is whatever the base left after being fully
drained — the outermost/bottom frame.

**Concrete failure:** install `MultiFunctionListenerFactory(logging, custom)` (the whole point of the
multiplexer) on a module run by the **default** engine (wazevo); any listener that walks the stack sees correct
`ProgramCounter()` per frame but the **same bottom-frame `Definition()`/`DebugName()` for all frames**. _(agent
runtime-verified: got `[$0,$0,$0]` where `[$2,$1,$0]` was expected.)_ The interpreter is unaffected (its
`Function()` returns a fresh value per frame). Distinct from the `NewStackIterator` reversal bug in the
2026-07-05 report — different type, different call path. **Direction:** buffer the per-frame `Definition()` /
`SourceOffset` values (snapshot each frame), not the shared iterator handle.

### U27 — [UPSTREAM] wazevo `SourceOffsetForPC` nil-derefs on an unknown PC — Low — PLAUSIBLE
**`internal/engine/wazevo/call_engine.go:874-879`.** `cm := si.eng.compiledModuleOfAddr(upc); return
cm.getSourceOffset(upc)` has no nil check, yet `compiledModuleOfAddr` returns nil when the address is in no live
module (owning module concurrently `DeleteCompiledModule`'d, or a listener passes a PC not produced by `Next()`).
Every other consumer of `compiledModuleOfAddr` guards nil (`:223, :848`); the interpreter equivalent is
defensive. Result: a panic *inside* stack-trace/source-offset resolution — error reporting itself faults.
PLAUSIBLE (needs the stale-PC or concurrent-delete window). **Direction:** return 0 when `cm == nil`.

### U28 — [UPSTREAM] DWARF inlined-frame formatting panics on a negative call-file index — Low — PLAUSIBLE
**`internal/wasmdebug/dwarf.go:191-198`.** `fileIndex, ok := inlined.Val(dwarf.AttrCallFile).(int64); … else if
fileIndex >= int64(len(files)) { return }; fileName := files[fileIndex]`. The guard is upper-bound only; a
negative `int64` from ill-formed DWARF passes it and `files[fileIndex]` panics — a crash while *formatting a
stack trace*, exactly when the runtime is already reporting another error. The adjacent comment says the code
guards "against ill-formed DWARF info," so the negative case is an oversight. **Direction:** also reject
`fileIndex < 0`.

### U29 — [UPSTREAM] `GetCompilationWorkers` clamps the minimum but not the maximum — Low — CONFIRMED
**`experimental/compilationworkers.go:16-19`** returns `max(workers, 1)`; a caller passing a huge value flows
into `wg.Add(workers)` / `for range workers { go … }` (`engine.go:309-311`), spawning that many goroutines
(they exit quickly once the count exceeds `len(CodeSection)`, but the stacks are allocated). User-controlled
config, so low severity. **Direction:** also clamp to `min(workers, len(CodeSection))` (or `NumCPU`).

---

## 4. Design tensions

**T1 — Untrusted `.wasm` decode/validate has no panic firewall.** `CompileModule` wraps *runtime execution*
in `recover` but not *decoding/validation*, yet the decoder/validator contains direct `body[pc]` indexing and
attacker-count-driven loops (U1) plus attacker-count `make()` calls (the upstream-accepted unbounded-alloc
pattern). One malformed module in an exception-handling-enabled host crashes the process. The fuzz corpus keeps
the *known* shapes safe, but the boundary's safety rests on "no unhandled panic reaches here," which is not
enforced. Alternative: a `defer/recover` translating any decode/validate panic into a validation error — cheap
insurance for a fully-untrusted boundary — plus bounding the vector counts that drive allocation.

**T2 — The `Icmp(Band,0)`→flags peephole is duplicated per backend and wrong in both.** U16 (amd64) and U17
(arm64) are the same optimization implemented twice, and each got a *different* corner wrong (commuted operand
order vs. `ANDS` C-flag semantics). Two independent, hand-written, per-ISA copies of one peephole is a
structural smell: there is no shared "these SSA conditions are safe to fold to a logical-flag instruction"
predicate, so each backend re-derives (and mis-derives) the eq/ne-only precondition. Alternative: a shared
SSA-level helper that answers "can this Icmp condition consume AND-flags?" (only `eq`/`ne`), used by every
backend's fold, so the precondition is stated once.

**T3 — Guest-controlled magnitudes drive host allocations in several places with no cap.** `fd_renumber`'s
target fd (U5), the decoder's vector counts, and the try-table cache counts (fork report C25) all let a small
input request an enormous allocation. wazero's model ("the whole binary is in memory; counts are `uint32`") is
defensible for decode, but `fd_renumber` is a *runtime* guest call with no such excuse, and the fatal-OOM
failure mode (uncatchable) is worse than a trap. Alternative: a uniform "bounded allocation" rule for any
size/count that crosses from guest control into a Go `make()` — cap and convert overflow to a trap/error.

**T4 — Writable OS-backed mounts are presented as a sandbox but aren't one.** The CLI's headline `--mount`
feature (U6, U7, U9) combines a symlink escape (U6), a silent non-directory fall-through (U7), and an
accidental-cwd exposure (U9). The affordance ("mount a host dir, the guest is sandboxed to it") over-promises:
against a *hostile* guest with write access there is no containment without `openat2`/`RESOLVE_BENEATH`.
Alternative: either implement kernel-enforced containment, or document `--mount` writable dirs as a
convenience, not a security boundary, and default to read-only.

**T5 — The `StackIterator`/`InternalFunction` contract invites use-after-advance bugs.** The wazevo
`StackIterator` returns *itself* from `Function()` and mutates `currentDef` on every `Next()`
(`call_engine.go:865`), so any code that stores an `InternalFunction` and reads it after advancing gets stale
data. This has now produced *two* independent CONFIRMED bugs in the same package — the `NewStackIterator`
frame/definition reversal (2026-07-05 report) and the `MultiFunctionListenerFactory` per-frame buffering (U26)
— plus a nil-deref (U27). The interface's shape ("here is a handle to the current function") reads as if the
handle is stable, but it is a live cursor. Alternative: make `Function()`/`Definition()` return an immutable
value snapshot per frame (as the interpreter already does), so buffering or deferring a frame is safe by
construction rather than a latent trap each consumer must know to avoid.

## 5. Expectation gaps (expected X, found Y)

- **Expected** `CompileModule` on a malformed module to return an error. **Found** it can panic and crash the
  host (U1; also U15 during emscripten export).
- **Expected** `fd_renumber` to a large fd to return `EBADF`/`ENOMEM`. **Found** it tries to allocate ~17 GB
  and fatally OOMs the host (U5).
- **Expected** a guest confined to a `--mount`ed directory to stay inside it. **Found** it can create a
  symlink and read `/etc/passwd` (U6).
- **Expected** an invalid `--mount`/`--listen` to abort with a non-zero exit. **Found** the module runs anyway,
  often exiting 0, sometimes with valid listeners silently dropped (U7, U8).
- **Expected** `gt_u (and a b) 0` and `0 <s (and a b)` to compute the obvious booleans. **Found** the compiler
  backends miscompile them to constant / inverted branches (U16, U17).
- **Expected** the CLI README's install command to install this binary. **Found** it installs upstream (U11).

## 6. Open questions

1. **Exception-handling exposure:** does any intended deployment enable `CoreFeaturesExceptionHandling` on
   untrusted input? That decides whether U1 is urgent or latent.
2. **Codegen trigger reachability:** which real toolchains emit `and`→unsigned/ordered-compare-vs-0→branch
   without canonicalizing to `ne`? If any do (hand-written wat, certain optimizers), U16/U17 are live in
   production, not just theoretically.
3. **Upstreaming:** U1, U5, U6, U15, U16, U17 are all upstream `tetratelabs/wazero` bugs. Does this fork carry
   local fixes (and diverge), or report/upstream them and wait? U16/U17 in particular deserve an upstream issue.
4. **Mount threat model:** is `--mount` of a writable host directory meant to be a security boundary against a
   hostile guest, or only a convenience for trusted guests? The docs don't say (U6/T4).
5. **Rec-group type-ID confusion (U23):** can a forward concrete-ref in a mutually-recursive rec group reach
   `structuralValueTypeName` with an unassigned `tid==0`, and if so does it let two structurally-distinct types
   share a `FunctionTypeID` that `call_indirect` then treats as equal? This needs a targeted trace into the
   `call_indirect` type check with the GC/typed-refs feature enabled — it is the one open item with potential
   memory-safety (sandbox-escape) impact, so it should be resolved before relying on typed function references
   for untrusted modules.

## 7. Sound areas (verified, no finding)

Recorded so the maintainer knows where effort went and what held up: WASI **path resolution** (`path.Clean` +
`fs.ValidPath`), the **fd table** indexing/close/reuse, and the **ReadFS** read-only wrapper; the **fd
lifecycle** (double-close guarded by `Closed` CAS) and module registry locking; **iovec/readdir** bounds and
overflow guards; the **interpreter numerics** in full (trunc/sat, min/max signed-zero + NaN, round-half-even,
div/rem traps, shift masking, SIMD saturation/lane-width, atomics alignment, memory.copy/fill bounds — all
spec-correct); the **amd64** idiv/shift-CL/movzx-movsx/addressing/select/regalloc-swap/SIMD paths and the trap
islands; the **arm64** idiv overflow, fcvt trap/saturate, atomics, constant materialization, br_table clamp,
and the SIMD encodings; the **SSA passes** (deadcode preserving traps, redundant-phi preserving loop carries,
critical-edge split); the **frontend** known-safe-bounds elision (sound across grow/call/block-merge); the
**filecache** (hex-of-SHA-256 paths — no traversal; atomic `CreateTemp`+`Sync`+`Rename`; CRC + version keying;
CPU-feature keying) and **W^X** enforcement on code segments; and the **reflection host-func adaptation**
(`gofunc.go`) param/result marshalling and `api` encode/decode helpers. The **pre-applied memory skip**
(fork-new) was re-reviewed here and is sound for its host-trusted threat model (its contract/doc issues live in
the 2026-07-05 fork report, C2/C5/C6).

The second wave added more cleared ground: the **instruction encoders** in both backends (the arm64
logical/bitmask-immediate encoder was brute-forced against the ARM reference decoder across all ~11k legal
values with zero mismatches; branch-range enforcement, ModRM/SIB/REX, imm8-vs-imm32 selection, SP-vs-XZR all
correct); the **wait/notify non-timeout path** (correctly serialized by `w.mux`, no lost/spurious wakeup — the
only gap is the timeout overlap, U19); **shared-memory "can't move"** enforcement and the imported-shared length
atomicity; **table/element bounds** (trap-before-write holds for `table.init/copy/fill/grow`); the
**snapshotter/checkpoint** restore (foreign-snapshot re-panic, independent stack clone), **CloseNotifier**
once-only ordering, and the **`sortedCompiledModules`** PC→module boundary lookup. Numerous adversarial
hypotheses (gofunc ctx/mod marshalling, idiv flag clobbers, fcvt inexact-flag misfire, SSA dropping trapping
loads, filecache traversal, iovec overflow, atomic 64-bit alignment on 32-bit hosts, encoder field truncation,
snapshot cross-frame restore) were raised and disproved.
