package adhoc

import (
	"context"
	"runtime"
	"strings"
	"testing"

	wazero "github.com/mgilbir/andsifr"
	"github.com/mgilbir/andsifr/api"
	"github.com/mgilbir/andsifr/experimental"
	"github.com/mgilbir/andsifr/internal/platform"
	"github.com/mgilbir/andsifr/internal/testing/binaryencoding"
	"github.com/mgilbir/andsifr/internal/testing/require"
	"github.com/mgilbir/andsifr/internal/wasm"
)

// typedRefFeatures enables the typed function references proposal.
var typedRefFeatures = api.CoreFeaturesV2 | experimental.CoreFeaturesTypedFunctionReferences

// TestE2E_concrete_ref_table_import ensures that importing a table whose
// element type is a concrete reference type compares the referenced types
// structurally across modules: the same type may live at different type
// section indexes in the exporter and the importer. Previously the comparison
// was raw ValueType equality (module-local index bits), producing spurious
// mismatches — and, with colliding indexes, linking mismatched tables (C13 in
// codebase-audit-2026-10-18.md).
func TestE2E_concrete_ref_table_import(t *testing.T) {
	ctx := context.Background()

	// Exporter: $0 = (i32)->(i32); table "t" of (ref null $0).
	exporterWasm := binaryencoding.EncodeModule(&wasm.Module{
		TypeSection:   []wasm.FunctionType{{Params: []wasm.ValueType{wasm.ValueTypeI32}, Results: []wasm.ValueType{wasm.ValueTypeI32}}},
		TableSection:  []wasm.Table{{Type: wasm.ValueTypeConcreteRef(0, true), Min: 1}},
		ExportSection: []wasm.Export{{Name: "t", Type: wasm.ExternTypeTable, Index: 0}},
		NameSection:   &wasm.NameSection{ModuleName: "m"},
	})

	newImporter := func(typeIndex uint32, params, results []wasm.ValueType) []byte {
		return binaryencoding.EncodeModule(&wasm.Module{
			// $0 is a decoy so that the imported type lands at a different
			// index than in the exporter.
			TypeSection: []wasm.FunctionType{
				{},
				{Params: params, Results: results},
			},
			ImportTableCount: 1,
			ImportSection: []wasm.Import{{
				Module: "m", Name: "t",
				Type: wasm.ExternTypeTable,
				DescTable: wasm.Table{
					Type: wasm.ValueTypeConcreteRef(typeIndex, true),
					Min:  1,
				},
			}},
		})
	}

	t.Run("structurally equivalent type at a different index links", func(t *testing.T) {
		r := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfig().WithCoreFeatures(typedRefFeatures))
		defer r.Close(ctx)

		_, err := r.Instantiate(ctx, exporterWasm)
		require.NoError(t, err)

		// (ref null $1) where $1 = (i32)->(i32) is structurally identical to
		// the exporter's $0.
		_, err = r.Instantiate(ctx, newImporter(1,
			[]wasm.ValueType{wasm.ValueTypeI32}, []wasm.ValueType{wasm.ValueTypeI32}))
		require.NoError(t, err)
	})

	t.Run("structurally different type is refused", func(t *testing.T) {
		r := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfig().WithCoreFeatures(typedRefFeatures))
		defer r.Close(ctx)

		_, err := r.Instantiate(ctx, exporterWasm)
		require.NoError(t, err)

		_, err = r.Instantiate(ctx, newImporter(1,
			[]wasm.ValueType{wasm.ValueTypeI64}, []wasm.ValueType{wasm.ValueTypeI64}))
		require.Error(t, err)
		require.True(t, strings.Contains(err.Error(), "table type mismatch"))
	})
}

// v128Const returns the bytes of a v128.const instruction with the given bytes.
func v128Const(b [16]byte) []byte {
	body := []byte{wasm.OpcodeVecPrefix, byte(wasm.OpcodeVecV128Const)}
	return append(body, b[:]...)
}

// TestE2E_throw_v128_param ensures that a tag with a v128 parameter stores and
// reloads the parameter correctly. Params are slot-packed (one uint64 slot per
// scalar, two per v128): previously the exception object was sized by
// parameter count, so the 16-byte store of a v128 param overflowed the Go heap
// (C14 in codebase-audit-2026-10-18.md).
func TestE2E_throw_v128_param(t *testing.T) {
	ctx := context.Background()
	features := api.CoreFeaturesV2 | experimental.CoreFeaturesExceptionHandling

	// (tag $tag (param v128))
	// (func (export "test") (result i32)
	//   (block (result v128)
	//     (try_table (catch $tag 0)
	//       (v128.const <lane0=66, rest 0>))
	//          -- unreachable: always throws
	//     )
	//   )
	//   (i8x16.extract_lane_s 0))
	mainBody := append([]byte{
		wasm.OpcodeBlock, byte(wasm.ValueTypeV128), // block (result v128)
		wasm.OpcodeTryTable, byte(wasm.ValueTypeV128), // try_table (result v128)
		0x01,                            // one catch clause
		wasm.CatchKindCatch, 0x00, 0x00, // catch $tag 0 -> label 0
	}, v128Const([16]byte{66})...)
	mainBody = append(mainBody,
		wasm.OpcodeThrow, 0x00, // throw $tag
		wasm.OpcodeEnd,                                                    // end try_table (unreachable after throw)
		wasm.OpcodeEnd,                                                    // end block: handler receives the v128 param
		wasm.OpcodeVecPrefix, byte(wasm.OpcodeVecI8x16ExtractLaneS), 0x00, // i8x16.extract_lane_s 0
		wasm.OpcodeEnd, // end function
	)

	bin := binaryencoding.EncodeModule(&wasm.Module{
		TypeSection: []wasm.FunctionType{
			{Params: []wasm.ValueType{wasm.ValueTypeV128}}, // $0: tag type
			{Results: []wasm.ValueType{wasm.ValueTypeI32}}, // $1: "test"
		},
		TagSection:      []wasm.Tag{{Type: 0}},
		FunctionSection: []wasm.Index{1},
		ExportSection:   []wasm.Export{{Name: "test", Type: wasm.ExternTypeFunc, Index: 0}},
		CodeSection:     []wasm.Code{{Body: mainBody}},
	})

	t.Run("compiler", func(t *testing.T) {
		if !platform.CompilerSupported() {
			t.Skip()
		}
		r := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfigCompiler().WithCoreFeatures(features))
		defer r.Close(ctx)
		mod, err := r.Instantiate(ctx, bin)
		require.NoError(t, err)
		res, err := mod.ExportedFunction("test").Call(ctx)
		require.NoError(t, err)
		require.Equal(t, int32(66), api.DecodeI32(res[0]))
	})

	t.Run("interpreter", func(t *testing.T) {
		r := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfigInterpreter().WithCoreFeatures(features))
		defer r.Close(ctx)
		mod, err := r.Instantiate(ctx, bin)
		require.NoError(t, err)
		res, err := mod.ExportedFunction("test").Call(ctx)
		require.NoError(t, err)
		require.Equal(t, int32(66), api.DecodeI32(res[0]))
	})
}

// TestE2E_exnref_gc_root ensures that an exnref captured by the guest survives
// Go garbage collection: exceptions are rooted in the Store, because guest
// exnrefs are raw pointers invisible to the Go GC (C15 in
// codebase-audit-2026-10-18.md). Note: without the root the failure is
// probabilistic (Go does not zero freed memory before reuse), so this test
// primarily pins the correct behaviour rather than reproducibly failing
// without the fix.
func TestE2E_exnref_gc_root(t *testing.T) {
	ctx := context.Background()
	features := api.CoreFeaturesV2 | experimental.CoreFeaturesExceptionHandling

	// (tag $tag (param i32))
	//
	// (func (export "save") (result exnref)
	//   (block (result exnref)
	//     (try_table (catch_all_ref 0)
	//       (i32.const 9) (throw $tag))))
	//
	// (func (export "rethrow") (param exnref) (result i32)
	//   (block (result i32)
	//     (try_table (catch $tag 0)
	//       (local.get 0) (throw_ref))))
	//
	// (func (export "throwAnother") (result i32)
	//   (block (result i32)
	//     (try_table (catch $tag 0)
	//       (i32.const 111) (throw $tag))))
	saveBody := []byte{
		wasm.OpcodeBlock, byte(wasm.ValueTypeExnref), // block (result exnref)
		wasm.OpcodeTryTable, byte(wasm.ValueTypeExnref), // try_table (result exnref)
		0x01, wasm.CatchKindCatchAllRef, 0x00, // catch_all_ref -> label 0
		wasm.OpcodeI32Const, 9,
		wasm.OpcodeThrow, 0x00,
		wasm.OpcodeEnd, // end try_table (unreachable)
		wasm.OpcodeEnd, // end block -> [exnref]
		wasm.OpcodeLocalSet, 0x00,
		wasm.OpcodeBlock, byte(wasm.ValueTypeI32), // block (result i32)
		wasm.OpcodeTryTable, byte(wasm.ValueTypeI32), // try_table (result i32)
		0x01, wasm.CatchKindCatch, 0x00, 0x00, // catch $tag 0 -> label 0
		wasm.OpcodeI32Const, 60,
		wasm.OpcodeThrow, 0x00,
		wasm.OpcodeEnd, // end try_table (unreachable)
		wasm.OpcodeEnd, // end block -> [i32]
		wasm.OpcodeDrop,
		wasm.OpcodeLocalGet, 0x00,
		wasm.OpcodeEnd, // end function -> [exnref]
	}
	rethrowBody := []byte{
		wasm.OpcodeBlock, byte(wasm.ValueTypeI32), // block (result i32)
		wasm.OpcodeTryTable, byte(wasm.ValueTypeI32), // try_table (result i32)
		0x01, wasm.CatchKindCatch, 0x00, 0x00, // catch $tag 0 -> label 0
		wasm.OpcodeLocalGet, 0x00,
		wasm.OpcodeThrowRef,
		wasm.OpcodeEnd, // end try_table (unreachable)
		wasm.OpcodeEnd, // end block: catch delivered the tag's i32 param
		wasm.OpcodeEnd, // end function
	}
	throwAnotherBody := []byte{
		wasm.OpcodeBlock, byte(wasm.ValueTypeI32),
		wasm.OpcodeTryTable, byte(wasm.ValueTypeI32),
		0x01, wasm.CatchKindCatch, 0x00, 0x00,
		wasm.OpcodeI32Const, 60,
		wasm.OpcodeThrow, 0x00,
		wasm.OpcodeEnd,
		wasm.OpcodeEnd,
		wasm.OpcodeEnd, // end function
	}

	bin := binaryencoding.EncodeModule(&wasm.Module{
		TypeSection: []wasm.FunctionType{
			{Params: []wasm.ValueType{wasm.ValueTypeI32}},                                                  // $0: tag type
			{Results: []wasm.ValueType{wasm.ValueTypeExnref}},                                              // $1: save
			{Params: []wasm.ValueType{wasm.ValueTypeExnref}, Results: []wasm.ValueType{wasm.ValueTypeI32}}, // $2: rethrow
			{Results: []wasm.ValueType{wasm.ValueTypeI32}},                                                 // $3: throwAnother
		},
		TagSection:      []wasm.Tag{{Type: 0}},
		FunctionSection: []wasm.Index{1, 2, 3},
		ExportSection: []wasm.Export{
			{Name: "save", Type: wasm.ExternTypeFunc, Index: 0},
			{Name: "rethrow", Type: wasm.ExternTypeFunc, Index: 1},
			{Name: "throwAnother", Type: wasm.ExternTypeFunc, Index: 2},
		},
		CodeSection: []wasm.Code{
			{LocalTypes: []wasm.ValueType{wasm.ValueTypeExnref}, Body: saveBody},
			{Body: rethrowBody},
			{Body: throwAnotherBody},
		},
	})

	run := func(t *testing.T, cfg wazero.RuntimeConfig) {
		r := wazero.NewRuntimeWithConfig(ctx, cfg.WithCoreFeatures(features))
		defer r.Close(ctx)
		mod, err := r.Instantiate(ctx, bin)
		require.NoError(t, err)

		// Capture exnref A carrying the payload 9. save also throws a second
		// exception on the SAME call engine, destroying any single-slot root
		// (e.g. a "latest exception" field) that pointed at A.
		res, err := mod.ExportedFunction("save").Call(ctx)
		require.NoError(t, err)
		exnrefA := res[0]

		// Give the GC a chance to collect the exception if it is not rooted.
		// The churn forces the allocator to reuse whatever memory A occupied
		// when it was collected; without the store-level root this makes the
		// dangling exnref read fail, with it the payload survives.
		runtime.GC()
		churn := make([]*[48]byte, 0, 20000)
		for i := 0; i < 20000; i++ {
			churn = append(churn, &[48]byte{})
		}
		runtime.KeepAlive(churn) // alive until here, so the allocations overlap the freed span
		runtime.GC()
		runtime.GC()

		// throw_ref A: the exception must still be alive and carry payload 9.
		res, err = mod.ExportedFunction("rethrow").Call(ctx, exnrefA)
		require.NoError(t, err)
		require.Equal(t, int32(9), api.DecodeI32(res[0]))
	}

	t.Run("compiler", func(t *testing.T) {
		if !platform.CompilerSupported() {
			t.Skip()
		}
		run(t, wazero.NewRuntimeConfigCompiler())
	})

	t.Run("interpreter", func(t *testing.T) {
		run(t, wazero.NewRuntimeConfigInterpreter())
	})
}
