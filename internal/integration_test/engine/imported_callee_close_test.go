package adhoc

import (
	"context"
	"fmt"
	"testing"

	wazero "github.com/mgilbir/andsifr"
	"github.com/mgilbir/andsifr/api"
	"github.com/mgilbir/andsifr/experimental"
	"github.com/mgilbir/andsifr/internal/platform"
	"github.com/mgilbir/andsifr/internal/testing/binaryencoding"
	"github.com/mgilbir/andsifr/internal/testing/require"
	"github.com/mgilbir/andsifr/internal/wasm"
)

type closingCalleeMemory struct {
	reallocations, frees int
	buffer               []byte
}

func (m *closingCalleeMemory) Reallocate(size uint64) []byte {
	m.reallocations++
	next := make([]byte, size)
	copy(next, m.buffer)
	m.buffer = next
	return next
}
func (m *closingCalleeMemory) Free() { m.frees++ }

// Calls through imports and tables do not reenter the Go call engine. The
// allocation must survive closing its owner, including a subsequent memory.grow.
func TestE2E_imported_callee_close_defers_free(t *testing.T) {
	for _, tc := range []struct {
		name   string
		config wazero.RuntimeConfig
	}{{"interpreter", wazero.NewRuntimeConfigInterpreter()}, {"compiler", wazero.NewRuntimeConfigCompiler()}} {
		for _, crossRuntime := range []bool{false, true} {
			for _, mode := range []string{"direct", "indirect", "imported memory"} {
				t.Run(fmt.Sprintf("%s/cross-runtime=%v/%s", tc.name, crossRuntime, mode), func(t *testing.T) {
					if tc.name == "compiler" && !platform.CompilerSupported() {
						t.Skip("compiler not supported")
					}
					allocation := &closingCalleeMemory{}
					ctx := experimental.WithMemoryAllocator(context.Background(), experimental.MemoryAllocatorFunc(func(uint64, uint64) experimental.LinearMemory { return allocation }))
					r := wazero.NewRuntimeWithConfig(ctx, tc.config)
					defer r.Close(ctx)
					callerRuntime := r
					if crossRuntime {
						callerRuntime = wazero.NewRuntimeWithConfig(ctx, tc.config)
						defer callerRuntime.Close(ctx)
					}
					ownerName := "callee"
					if mode == "imported memory" {
						ownerName = "owner"
						owner := binaryencoding.EncodeModule(&wasm.Module{
							MemorySection: &wasm.Memory{Min: 1},
							ExportSection: []wasm.Export{{Name: "memory", Type: wasm.ExternTypeMemory, Index: 0}},
						})
						_, err := r.InstantiateWithConfig(ctx, owner, wazero.NewModuleConfig().WithName(ownerName))
						require.NoError(t, err)
					}
					_, err := r.NewHostModuleBuilder("env").NewFunctionBuilder().WithFunc(func(ctx context.Context) {
						require.NoError(t, r.Module(ownerName).Close(ctx))
						require.Equal(t, 0, allocation.frees, "memory freed while callee remains on the guest stack")
					}).Export("close").Instantiate(ctx)
					require.NoError(t, err)
					callee := &wasm.Module{
						TypeSection:         []wasm.FunctionType{{}},
						ImportFunctionCount: 1,
						ImportSection:       []wasm.Import{{Module: "env", Name: "close", Type: wasm.ExternTypeFunc, DescFunc: 0}},
						MemorySection:       &wasm.Memory{Min: 1},
						FunctionSection:     []wasm.Index{0},
						ExportSection:       []wasm.Export{{Name: "f", Type: wasm.ExternTypeFunc, Index: 1}},
						CodeSection: []wasm.Code{{Body: []byte{
							wasm.OpcodeCall, 0,
							wasm.OpcodeI32Const, 1, wasm.OpcodeMemoryGrow, 0, wasm.OpcodeDrop,
							wasm.OpcodeI32Const, 0, wasm.OpcodeI32Load, 2, 0, wasm.OpcodeDrop,
							wasm.OpcodeEnd,
						}}},
					}
					if mode == "imported memory" {
						callee.MemorySection = nil
						callee.ImportMemoryCount = 1
						callee.ImportSection = append(callee.ImportSection, wasm.Import{
							Module: "owner", Name: "memory", Type: wasm.ExternTypeMemory, DescMem: &wasm.Memory{Min: 1},
						})
					}
					_, err = r.InstantiateWithConfig(ctx, binaryencoding.EncodeModule(callee), wazero.NewModuleConfig().WithName("callee"))
					require.NoError(t, err)
					caller := &wasm.Module{
						TypeSection:         []wasm.FunctionType{{}},
						ImportFunctionCount: 1,
						ImportSection:       []wasm.Import{{Module: "callee", Name: "f", Type: wasm.ExternTypeFunc, DescFunc: 0}},
						FunctionSection:     []wasm.Index{0},
						ExportSection:       []wasm.Export{{Name: "run", Type: wasm.ExternTypeFunc, Index: 1}},
						CodeSection:         []wasm.Code{{Body: []byte{wasm.OpcodeCall, 0, wasm.OpcodeEnd}}},
					}
					if mode == "indirect" {
						caller.TableSection = []wasm.Table{{Type: wasm.RefTypeFuncref, Min: 1}}
						caller.ElementSection = []wasm.ElementSegment{{
							Mode: wasm.ElementModeActive, Type: wasm.RefTypeFuncref,
							OffsetExpr: wasm.NewConstantExpressionFromI32(0),
							Init:       []wasm.ConstantExpression{wasm.NewConstantExpressionFromOpcode(wasm.OpcodeRefFunc, []byte{0})},
						}}
						caller.CodeSection[0].Body = []byte{wasm.OpcodeI32Const, 0, wasm.OpcodeCallIndirect, 0, 0, wasm.OpcodeEnd}
					}
					callerCtx := experimental.WithImportResolver(ctx, func(name string) api.Module { return r.Module(name) })
					mod, err := callerRuntime.Instantiate(callerCtx, binaryencoding.EncodeModule(caller))
					require.NoError(t, err)
					_, err = mod.ExportedFunction("run").Call(ctx)
					require.NoError(t, err)
					require.Equal(t, 2, allocation.reallocations, "in-flight growth must use the original allocator")
					require.Equal(t, 0, allocation.frees, "live imports must retain the allocation after the call returns")
					require.NoError(t, mod.Close(ctx))
					if mode == "imported memory" {
						require.Equal(t, 0, allocation.frees, "the callee still imports the owner's memory")
						require.NoError(t, r.Module("callee").Close(ctx))
					}
					require.Equal(t, 1, allocation.frees, "the last importer must release the allocation exactly once")
				})
			}
		}
	}
}
