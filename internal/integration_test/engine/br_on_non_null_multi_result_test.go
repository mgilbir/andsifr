package adhoc

import (
	"context"
	"testing"

	wazero "github.com/mgilbir/andsifr"
	"github.com/mgilbir/andsifr/api"
	"github.com/mgilbir/andsifr/experimental"
	"github.com/mgilbir/andsifr/internal/platform"
	"github.com/mgilbir/andsifr/internal/testing/binaryencoding"
	"github.com/mgilbir/andsifr/internal/testing/require"
	"github.com/mgilbir/andsifr/internal/wasm"
)

// TestE2E_br_on_non_null_multi_result ensures the interpreter's br_on_non_null
// delivers the correct values to a multi-result label: the ref is popped at
// runtime and re-pushed as the last label argument, so the drop range must
// keep one fewer value. Previously the drop kept the frame's full result
// count, dropping a real argument and stranding a stale operand between the
// label arguments and the ref (C42 in codebase-audit-2026-10-18.md).
func TestE2E_br_on_non_null_multi_result(t *testing.T) {
	ctx := context.Background()
	// br_on_non_null is part of typed function references.
	features := api.CoreFeaturesV2 | experimental.CoreFeaturesTypedFunctionReferences

	// (type $bt (func (result i32 funcref)))
	// (func (export "test") (result i32)
	//   (block (type $bt)
	//     (i32.const 7)
	//     (ref.func $test)
	//     (br_on_non_null 0))
	//   (drop))
	body := []byte{
		wasm.OpcodeBlock, 0x01, // block (type 1): (result i32 funcref)
		wasm.OpcodeI32Const, 99, // junk: stranded on the stack when the drop over-keeps
		wasm.OpcodeI32Const, 7,
		wasm.OpcodeRefFunc, 0x00,
		wasm.OpcodeBrOnNonNull, 0x00,
		// Null fall-through: rebuild the block's results (validation
		// requires them even though ref.func never returns null).
		wasm.OpcodeDrop,
		wasm.OpcodeDrop,
		wasm.OpcodeI32Const, 7,
		wasm.OpcodeRefNull, byte(wasm.ValueTypeFuncref),
		wasm.OpcodeEnd, // end block -> [i32, funcref]
		wasm.OpcodeDrop,
		wasm.OpcodeEnd, // end function
	}

	bin := binaryencoding.EncodeModule(&wasm.Module{
		TypeSection: []wasm.FunctionType{
			{Results: []wasm.ValueType{wasm.ValueTypeI32}},                        // $0: "test"
			{Results: []wasm.ValueType{wasm.ValueTypeI32, wasm.ValueTypeFuncref}}, // $1: block type
		},
		FunctionSection: []wasm.Index{0},
		ExportSection:   []wasm.Export{{Name: "test", Type: wasm.ExternTypeFunc, Index: 0}},
		TableSection:    []wasm.Table{{Type: wasm.ValueTypeFuncref, Min: 1}},
		// Active segment: declares func 0 for ref.func (the binaryencoding
		// helper does not support declarative segments).
		ElementSection: []wasm.ElementSegment{{
			Mode:       wasm.ElementModeActive,
			TableIndex: 0,
			Type:       wasm.ValueTypeFuncref,
			OffsetExpr: wasm.NewConstantExpressionFromI32(0),
			Init:       []wasm.ConstantExpression{wasm.NewConstantExpressionFromOpcode(wasm.OpcodeRefFunc, []byte{0})},
		}},
		CodeSection: []wasm.Code{{Body: body}},
	})

	run := func(t *testing.T, cfg wazero.RuntimeConfig) {
		r := wazero.NewRuntimeWithConfig(ctx, cfg)
		defer r.Close(ctx)
		mod, err := r.Instantiate(ctx, bin)
		require.NoError(t, err)
		res, err := mod.ExportedFunction("test").Call(ctx)
		require.NoError(t, err)
		require.Equal(t, int32(7), api.DecodeI32(res[0]))
	}

	t.Run("interpreter", func(t *testing.T) {
		run(t, wazero.NewRuntimeConfigInterpreter().WithCoreFeatures(features))
	})

	t.Run("compiler", func(t *testing.T) {
		if !platform.CompilerSupported() {
			t.Skip()
		}
		run(t, wazero.NewRuntimeConfigCompiler().WithCoreFeatures(features))
	})
}
