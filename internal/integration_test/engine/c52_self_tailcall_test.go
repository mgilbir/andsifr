package adhoc

import (
	"context"
	"testing"
	"time"

	wazero "github.com/mgilbir/andsifr"
	"github.com/mgilbir/andsifr/api"
	"github.com/mgilbir/andsifr/experimental"
	"github.com/mgilbir/andsifr/internal/platform"
	"github.com/mgilbir/andsifr/internal/testing/binaryencoding"
	"github.com/mgilbir/andsifr/internal/testing/require"
	"github.com/mgilbir/andsifr/internal/wasm"
)

// TestE2E_self_tail_call_terminates ensures a self tail call
// (return_call $self) observes WithCloseOnContextDone: it never passes a loop
// header, so without the dedicated check the function loops forever (C52 in
// codebase-audit-2026-10-18.md).
func TestE2E_self_tail_call_terminates(t *testing.T) {
	ctx := context.Background()
	features := api.CoreFeaturesV2 | experimental.CoreFeaturesTailCall

	// (func $spin (param i64) (result i64) (return_call $spin (local.get 0)))
	bin := binaryencoding.EncodeModule(&wasm.Module{
		TypeSection:     []wasm.FunctionType{{Params: []wasm.ValueType{wasm.ValueTypeI64}, Results: []wasm.ValueType{wasm.ValueTypeI64}}},
		FunctionSection: []wasm.Index{0},
		ExportSection:   []wasm.Export{{Name: "spin", Type: wasm.ExternTypeFunc, Index: 0}},
		CodeSection: []wasm.Code{{Body: []byte{
			wasm.OpcodeLocalGet, 0x00,
			wasm.OpcodeTailCallReturnCall, 0x00,
			wasm.OpcodeEnd,
		}}},
	})

	run := func(t *testing.T, cfg wazero.RuntimeConfig) {
		r := wazero.NewRuntimeWithConfig(ctx, cfg.WithCloseOnContextDone(true))
		defer r.Close(ctx)
		mod, err := r.Instantiate(ctx, bin)
		require.NoError(t, err)

		callCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
		defer cancel()
		done := make(chan error, 1)
		go func() {
			_, err := mod.ExportedFunction("spin").Call(callCtx, 1)
			done <- err
		}()
		select {
		case err := <-done:
			// Terminated: deadline exceeded (or context canceled) is expected.
			require.Error(t, err)
		case <-time.After(5 * time.Second):
			t.Fatal("self tail call never observed the context deadline")
		}
	}

	t.Run("compiler", func(t *testing.T) {
		if !platform.CompilerSupported() {
			t.Skip()
		}
		run(t, wazero.NewRuntimeConfigCompiler().WithCoreFeatures(features))
	})

	t.Run("interpreter", func(t *testing.T) {
		run(t, wazero.NewRuntimeConfigInterpreter().WithCoreFeatures(features))
	})
}
