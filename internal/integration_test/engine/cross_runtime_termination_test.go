package adhoc

import (
	"context"
	"testing"

	wazero "github.com/mgilbir/andsifr"
	"github.com/mgilbir/andsifr/api"
	"github.com/mgilbir/andsifr/experimental"
	"github.com/mgilbir/andsifr/internal/testing/binaryencoding"
	"github.com/mgilbir/andsifr/internal/testing/require"
	"github.com/mgilbir/andsifr/internal/wasm"
)

// TestE2E_cross_runtime_termination_inline_check ensures that a module compiled
// with WithCloseOnContextDone (whose loop headers load the entry module's Closed
// flag through ExecutionContext.entryModuleClosedPtr) can be called from a
// Runtime that does not use WithCloseOnContextDone. The entry callEngine only
// populated entryModuleClosedPtr when the *entry* module was compiled with
// ensureTermination, so the cross-Runtime call dereferenced a nil pointer and
// crashed the host process (C6 in codebase-audit-2026-10-18.md).
func TestE2E_cross_runtime_termination_inline_check(t *testing.T) {
	ctx := context.Background()

	// Callee: (func (export "loop10") (local i32)
	//   (i32.const 10) (local.set 0)
	//   (loop (br_if 0 (local.tee 0 (i32.sub (local.get 0) (i32.const 1))))))
	// A bounded loop: the inline termination check at the loop header is
	// executed on every iteration, which is all the repro needs.
	calleeWasm := binaryencoding.EncodeModule(&wasm.Module{
		TypeSection:     []wasm.FunctionType{{}},
		FunctionSection: []wasm.Index{0},
		ExportSection:   []wasm.Export{{Name: "loop10", Type: wasm.ExternTypeFunc, Index: 0}},
		CodeSection: []wasm.Code{{
			LocalTypes: []wasm.ValueType{wasm.ValueTypeI32},
			Body: []byte{
				wasm.OpcodeI32Const, 10,
				wasm.OpcodeLocalSet, 0,
				wasm.OpcodeLoop, 0x40,
				wasm.OpcodeLocalGet, 0,
				wasm.OpcodeI32Const, 1,
				wasm.OpcodeI32Sub,
				wasm.OpcodeLocalTee, 0,
				wasm.OpcodeBrIf, 0,
				wasm.OpcodeEnd,
				wasm.OpcodeEnd,
			},
		}},
	})

	// Caller: (import "callee" "loop10" (func $loop)) (func (export "run") (call $loop))
	callerWasm := binaryencoding.EncodeModule(&wasm.Module{
		TypeSection:         []wasm.FunctionType{{}},
		ImportFunctionCount: 1,
		ImportSection: []wasm.Import{{
			Module: "callee", Name: "loop10",
			Type:     wasm.ExternTypeFunc,
			DescFunc: 0,
		}},
		FunctionSection: []wasm.Index{0},
		ExportSection:   []wasm.Export{{Name: "run", Type: wasm.ExternTypeFunc, Index: 1}},
		CodeSection: []wasm.Code{{
			Body: []byte{wasm.OpcodeCall, 0, wasm.OpcodeEnd},
		}},
	})

	// Runtime B compiles the callee with WithCloseOnContextDone, so its loop
	// headers contain the inline termination check.
	rcB := wazero.NewRuntimeConfig().WithCloseOnContextDone(true)
	rB := wazero.NewRuntimeWithConfig(ctx, rcB)
	defer rB.Close(ctx)
	callee, err := rB.Instantiate(ctx, calleeWasm)
	require.NoError(t, err)

	// Runtime A does not use WithCloseOnContextDone; it imports the callee
	// through an ImportResolver, producing the cross-Runtime call.
	rA := wazero.NewRuntime(ctx)
	defer rA.Close(ctx)

	ctxResolve := experimental.WithImportResolver(ctx, func(name string) api.Module {
		if name == "callee" {
			return callee
		}
		return nil
	})

	caller, err := rA.Instantiate(ctxResolve, callerWasm)
	require.NoError(t, err)

	run := caller.ExportedFunction("run")
	require.NotNil(t, run)

	// Before the fix, this crashed the host process with a nil pointer
	// dereference at the callee's first loop header.
	_, err = run.Call(ctx)
	require.NoError(t, err)
}
