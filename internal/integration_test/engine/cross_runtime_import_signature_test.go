package adhoc

import (
	"context"
	"strings"
	"testing"

	wazero "github.com/mgilbir/andsifr"
	"github.com/mgilbir/andsifr/api"
	"github.com/mgilbir/andsifr/experimental"
	"github.com/mgilbir/andsifr/internal/testing/binaryencoding"
	"github.com/mgilbir/andsifr/internal/testing/require"
	"github.com/mgilbir/andsifr/internal/wasm"
)

// TestE2E_cross_runtime_import_signature ensures that importing a function from
// a module instantiated in another Runtime compares signatures structurally.
// FunctionTypeID is scoped to the Store that interned it, so comparing the raw
// IDs of a resolver-returned module (other Runtime) against the importing
// module's IDs was meaningless: structurally equal signatures could be
// rejected and, worse, mismatched ones accepted (C5 in
// codebase-audit-2026-10-18.md).
func TestE2E_cross_runtime_import_signature(t *testing.T) {
	ctx := context.Background()

	// Callee in runtime B: two types so that the interned FunctionTypeID of
	// ()->() differs from the importer's intern space.
	calleeWasm := binaryencoding.EncodeModule(&wasm.Module{
		TypeSection: []wasm.FunctionType{
			{Params: []wasm.ValueType{wasm.ValueTypeI32}, Results: []wasm.ValueType{wasm.ValueTypeI32}},
			{},
		},
		FunctionSection: []wasm.Index{1},
		ExportSection:   []wasm.Export{{Name: "f", Type: wasm.ExternTypeFunc, Index: 0}},
		CodeSection:     []wasm.Code{{Body: []byte{wasm.OpcodeEnd}}},
	})

	newCaller := func(importedType wasm.FunctionType, body []byte) []byte {
		return binaryencoding.EncodeModule(&wasm.Module{
			TypeSection:         []wasm.FunctionType{importedType, {}},
			ImportFunctionCount: 1,
			ImportSection: []wasm.Import{{
				Module: "callee", Name: "f",
				Type:     wasm.ExternTypeFunc,
				DescFunc: 0,
			}},
			FunctionSection: []wasm.Index{1},
			ExportSection:   []wasm.Export{{Name: "run", Type: wasm.ExternTypeFunc, Index: 1}},
			CodeSection:     []wasm.Code{{Body: body}},
		})
	}

	rB := wazero.NewRuntime(ctx)
	defer rB.Close(ctx)
	callee, err := rB.Instantiate(ctx, calleeWasm)
	require.NoError(t, err)

	rA := wazero.NewRuntime(ctx)
	defer rA.Close(ctx)

	ctxResolve := experimental.WithImportResolver(ctx, func(name string) api.Module {
		if name == "callee" {
			return callee
		}
		return nil
	})

	t.Run("structurally equal signature links", func(t *testing.T) {
		caller, err := rA.Instantiate(ctxResolve, newCaller(wasm.FunctionType{}, []byte{wasm.OpcodeCall, 0, wasm.OpcodeEnd}))
		require.NoError(t, err)
		_, err = caller.ExportedFunction("run").Call(ctx)
		require.NoError(t, err)
	})

	t.Run("structurally mismatched signature is rejected", func(t *testing.T) {
		// ()->(i32) declared; the callee exports ()->(). Valid within the
		// importer (the result is dropped), so only import linkage can reject it.
		mismatch := wasm.FunctionType{Results: []wasm.ValueType{wasm.ValueTypeI32}}
		_, err := rA.Instantiate(ctxResolve, newCaller(mismatch, []byte{wasm.OpcodeCall, 0, wasm.OpcodeDrop, wasm.OpcodeEnd}))
		require.Error(t, err)
		require.True(t, strings.Contains(err.Error(), "signature mismatch"))
	})
}
