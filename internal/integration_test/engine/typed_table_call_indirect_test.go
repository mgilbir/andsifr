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

// TestE2E_call_indirect_typed_table ensures call_indirect works on tables of
// concrete reference types ((ref null $t)): they are subtypes of funcref and
// usable by call_indirect under the typed function references proposal.
// Previously the validator rejected them (C75 in
// codebase-audit-2026-10-18.md).
func TestE2E_call_indirect_typed_table(t *testing.T) {
	ctx := context.Background()
	features := api.CoreFeaturesV2 | experimental.CoreFeaturesTypedFunctionReferences

	// $0: (i32)->(i32)      -- the indirect callee signature
	// $1: () -> (i32)       -- "test"
	// $2: (i32)->(i32)      -- dup of $0, to prove cross-index equivalence
	// (table $2 (ref null $2) ...) is validated, then call_indirect type $0.
	//
	// (func $f (type $0) (i32.const 42))
	// (func (export "test") (result i32)
	//   (i32.const 0)                     -- table offset
	//   (i32.const 1)                     -- argument
	//   (call_indirect $0 (table 0)))
	// (elem (i32.const 0) $f)
	body := []byte{
		// test function:
		wasm.OpcodeI32Const, 1, // argument
		wasm.OpcodeI32Const, 0, // table offset (top of stack)
		wasm.OpcodeCallIndirect, 0x00, 0x00, // type 0, table 0
		wasm.OpcodeEnd,
	}
	calleeBody := []byte{
		wasm.OpcodeI32Const, 42,
		wasm.OpcodeEnd,
	}

	bin := binaryencoding.EncodeModule(&wasm.Module{
		TypeSection: []wasm.FunctionType{
			{Params: []wasm.ValueType{wasm.ValueTypeI32}, Results: []wasm.ValueType{wasm.ValueTypeI32}}, // $0
			{Results: []wasm.ValueType{wasm.ValueTypeI32}},                                              // $1
			{Params: []wasm.ValueType{wasm.ValueTypeI32}, Results: []wasm.ValueType{wasm.ValueTypeI32}}, // $2 (dup)
		},
		FunctionSection: []wasm.Index{0, 1},
		TableSection:    []wasm.Table{{Type: wasm.ValueTypeConcreteRef(2, true), Min: 1}},
		ExportSection: []wasm.Export{
			{Name: "test", Type: wasm.ExternTypeFunc, Index: 1},
		},
		ElementSection: []wasm.ElementSegment{{
			Mode:       wasm.ElementModeActive,
			TableIndex: 0,
			Type:       wasm.ValueTypeConcreteRef(2, true),
			OffsetExpr: wasm.NewConstantExpressionFromI32(0),
			Init:       []wasm.ConstantExpression{wasm.NewConstantExpressionFromOpcode(wasm.OpcodeRefFunc, []byte{0})},
		}},
		CodeSection: []wasm.Code{{Body: calleeBody}, {Body: body}},
	})

	r := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfig().WithCoreFeatures(features))
	defer r.Close(ctx)
	mod, err := r.Instantiate(ctx, bin)
	require.NoError(t, err)
	res, err := mod.ExportedFunction("test").Call(ctx)
	require.NoError(t, err)
	require.Equal(t, int32(42), api.DecodeI32(res[0]))
}
