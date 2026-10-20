package wazero_test

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

// Poison released memory so a guest read after Free fails deterministically,
// without unmapping memory and crashing the test process.
type lifetimeMemory struct {
	buffer []byte
	frees  int
}

func (m *lifetimeMemory) Reallocate(size uint64) []byte {
	next := make([]byte, size)
	copy(next, m.buffer)
	m.buffer = next
	return next
}

func (m *lifetimeMemory) Free() {
	m.frees++
	for i := range m.buffer {
		m.buffer[i] = 85
	}
}

func (m *lifetimeMemory) PreappliedDataFor([32]byte) bool { return false }

func TestImportedMemoryLifetime(t *testing.T) {
	for _, engine := range []string{"interpreter", "compiler"} {
		for _, crossRuntime := range []bool{false, true} {
			for _, importFunction := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/cross-runtime=%v/function=%v", engine, crossRuntime, importFunction), func(t *testing.T) {
					config := wazero.NewRuntimeConfigInterpreter()
					if engine == "compiler" {
						if !platform.CompilerSupported() {
							t.Skip("compiler not supported")
						}
						config = wazero.NewRuntimeConfigCompiler()
					}
					ctx := context.Background()
					r := wazero.NewRuntimeWithConfig(ctx, config)
					defer r.Close(ctx)
					callerRuntime := r
					if crossRuntime {
						callerRuntime = wazero.NewRuntimeWithConfig(ctx, config)
						defer callerRuntime.Close(ctx)
					}
					allocation := &lifetimeMemory{}
					allocCtx := experimental.WithMemoryAllocator(ctx, experimental.MemoryAllocatorFunc(func(uint64, uint64) experimental.LinearMemory { return allocation }))
					readBody := []byte{wasm.OpcodeI32Const, 0, wasm.OpcodeI32Load8U, 0, 0, wasm.OpcodeEnd}
					owner, err := r.InstantiateWithConfig(allocCtx, binaryencoding.EncodeModule(&wasm.Module{
						MemorySection:   &wasm.Memory{Min: 1},
						TypeSection:     []wasm.FunctionType{{Results: []wasm.ValueType{wasm.ValueTypeI32}}},
						FunctionSection: []wasm.Index{0},
						CodeSection:     []wasm.Code{{Body: readBody}},
						ExportSection: []wasm.Export{
							{Name: "memory", Type: wasm.ExternTypeMemory},
							{Name: "read", Type: wasm.ExternTypeFunc},
						},
					}), wazero.NewModuleConfig().WithName("owner"))
					require.NoError(t, err)
					require.True(t, owner.Memory().WriteByte(0, 17))
					readerModule := &wasm.Module{
						TypeSection:       []wasm.FunctionType{{Results: []wasm.ValueType{wasm.ValueTypeI32}}},
						FunctionSection:   []wasm.Index{0},
						CodeSection:       []wasm.Code{{Body: readBody}},
						ImportSection:     []wasm.Import{{Module: "owner", Name: "memory", Type: wasm.ExternTypeMemory, DescMem: &wasm.Memory{Min: 1}}},
						ImportMemoryCount: 1,
						ExportSection:     []wasm.Export{{Name: "read", Type: wasm.ExternTypeFunc}},
					}
					if importFunction {
						readerModule.ImportSection = []wasm.Import{{Module: "owner", Name: "read", Type: wasm.ExternTypeFunc}}
						readerModule.ImportMemoryCount = 0
						readerModule.ImportFunctionCount = 1
						readerModule.CodeSection[0].Body = []byte{wasm.OpcodeCall, 0, wasm.OpcodeEnd}
						readerModule.ExportSection[0].Index = 1
					}
					resolveCtx := experimental.WithImportResolver(ctx, func(string) api.Module { return owner })
					reader, err := callerRuntime.Instantiate(resolveCtx, binaryencoding.EncodeModule(readerModule))
					require.NoError(t, err)
					// Keep a third module live to verify transitive retention.
					resolveReaderCtx := experimental.WithImportResolver(ctx, func(string) api.Module { return reader })
					last, err := callerRuntime.Instantiate(resolveReaderCtx, binaryencoding.EncodeModule(&wasm.Module{
						TypeSection:         []wasm.FunctionType{{Results: []wasm.ValueType{wasm.ValueTypeI32}}},
						ImportSection:       []wasm.Import{{Module: "reader", Name: "read", Type: wasm.ExternTypeFunc}},
						ImportFunctionCount: 1,
						FunctionSection:     []wasm.Index{0},
						ExportSection:       []wasm.Export{{Name: "read", Type: wasm.ExternTypeFunc, Index: 1}},
						CodeSection:         []wasm.Code{{Body: []byte{wasm.OpcodeCall, 0, wasm.OpcodeEnd}}},
					}))
					require.NoError(t, err)
					require.NoError(t, owner.Close(ctx))
					require.NoError(t, reader.Close(ctx))
					require.Equal(t, 0, allocation.frees)
					result, err := last.ExportedFunction("read").Call(ctx)
					require.NoError(t, err)
					require.Equal(t, []uint64{17}, result)
					require.NoError(t, last.Close(ctx))
					require.Equal(t, 1, allocation.frees)
				})
			}
		}
	}
}

func TestImportedMemoryPreservesContents(t *testing.T) {
	ctx := context.Background()
	r := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfigInterpreter())
	defer r.Close(ctx)
	allocation := &lifetimeMemory{}
	allocCtx := experimental.WithMemoryAllocator(ctx, experimental.MemoryAllocatorFunc(func(uint64, uint64) experimental.LinearMemory { return allocation }))
	owner, err := r.InstantiateWithConfig(allocCtx, binaryencoding.EncodeModule(&wasm.Module{
		MemorySection: &wasm.Memory{Min: 1},
		ExportSection: []wasm.Export{{Name: "memory", Type: wasm.ExternTypeMemory}},
	}), wazero.NewModuleConfig().WithName("owner"))
	require.NoError(t, err)
	require.True(t, owner.Memory().WriteByte(0, 17))
	_, err = r.Instantiate(ctx, binaryencoding.EncodeModule(&wasm.Module{
		ImportSection:     []wasm.Import{{Module: "owner", Name: "memory", Type: wasm.ExternTypeMemory, DescMem: &wasm.Memory{Min: 1}}},
		ImportMemoryCount: 1,
		DataSection:       []wasm.DataSegment{{OffsetExpression: wasm.NewConstantExpressionFromI32(1), Init: []byte{23}}},
	}))
	require.NoError(t, err)
	contents, ok := owner.Memory().Read(0, 2)
	require.True(t, ok)
	require.Equal(t, []byte{17, 23}, contents)
}

func TestFailedInstantiationReleasesMemory(t *testing.T) {
	for _, failure := range []string{"start trap", "data bounds", "import mismatch"} {
		t.Run(failure, func(t *testing.T) {
			ctx := context.Background()
			r := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfigInterpreter())
			defer r.Close(ctx)
			allocation := &lifetimeMemory{}
			allocCtx := experimental.WithMemoryAllocator(ctx, experimental.MemoryAllocatorFunc(func(uint64, uint64) experimental.LinearMemory { return allocation }))
			module := &wasm.Module{
				MemorySection:   &wasm.Memory{Min: 1},
				TypeSection:     []wasm.FunctionType{{}},
				FunctionSection: []wasm.Index{0},
				CodeSection:     []wasm.Code{{Body: []byte{wasm.OpcodeUnreachable, wasm.OpcodeEnd}}},
				StartSection:    new(wasm.Index),
			}
			if failure == "data bounds" {
				module.StartSection = nil
				module.DataSection = []wasm.DataSegment{{OffsetExpression: wasm.NewConstantExpressionFromI32(65536), Init: []byte{1}}}
			} else if failure == "import mismatch" {
				owner, err := r.InstantiateWithConfig(allocCtx, binaryencoding.EncodeModule(&wasm.Module{
					MemorySection: &wasm.Memory{Min: 1},
					ExportSection: []wasm.Export{{Name: "memory", Type: wasm.ExternTypeMemory}},
				}), wazero.NewModuleConfig().WithName("owner"))
				require.NoError(t, err)
				module.MemorySection = nil
				module.StartSection = nil
				module.ImportMemoryCount = 1
				module.ImportSection = []wasm.Import{{Module: "owner", Name: "memory", Type: wasm.ExternTypeMemory, DescMem: &wasm.Memory{Min: 2}}}
				_, err = r.Instantiate(ctx, binaryencoding.EncodeModule(module))
				require.Error(t, err)
				require.Equal(t, 0, allocation.frees)
				require.NoError(t, owner.Close(ctx))
				require.Equal(t, 1, allocation.frees, "failed import must release its dependency")
				return
			}
			_, err := r.Instantiate(allocCtx, binaryencoding.EncodeModule(module))
			require.Error(t, err)
			require.Equal(t, 1, allocation.frees, "failed instance must release memory immediately")
			require.NoError(t, r.Close(ctx))
			require.Equal(t, 1, allocation.frees, "runtime close must not free memory twice")
		})
	}
}

// A trapping start function does not undo element initialization. A live table
// can therefore call a failed instance, including one from a different runtime.
func TestFailedInstantiationPreservesEscapedFunction(t *testing.T) {
	for _, engine := range []string{"interpreter", "compiler"} {
		t.Run(engine, func(t *testing.T) {
			config := wazero.NewRuntimeConfigInterpreter()
			if engine == "compiler" {
				if !platform.CompilerSupported() {
					t.Skip("compiler not supported")
				}
				config = wazero.NewRuntimeConfigCompiler()
			}
			ctx := context.Background()
			r := wazero.NewRuntimeWithConfig(ctx, config)
			defer r.Close(ctx)
			owner, err := r.InstantiateWithConfig(ctx, binaryencoding.EncodeModule(&wasm.Module{
				TypeSection:     []wasm.FunctionType{{Results: []wasm.ValueType{wasm.ValueTypeI32}}},
				TableSection:    []wasm.Table{{Type: wasm.RefTypeFuncref, Min: 1}},
				FunctionSection: []wasm.Index{0},
				ExportSection: []wasm.Export{
					{Name: "table", Type: wasm.ExternTypeTable},
					{Name: "read", Type: wasm.ExternTypeFunc},
				},
				CodeSection: []wasm.Code{{Body: []byte{wasm.OpcodeI32Const, 0, wasm.OpcodeCallIndirect, 0, 0, wasm.OpcodeEnd}}},
			}), wazero.NewModuleConfig().WithName("owner"))
			require.NoError(t, err)
			calleeRuntime := wazero.NewRuntimeWithConfig(ctx, config)
			defer calleeRuntime.Close(ctx)
			allocation := &lifetimeMemory{}
			allocCtx := experimental.WithMemoryAllocator(ctx, experimental.MemoryAllocatorFunc(func(uint64, uint64) experimental.LinearMemory { return allocation }))
			allocCtx = experimental.WithImportResolver(allocCtx, func(string) api.Module { return owner })
			start := wasm.Index(1)
			_, err = calleeRuntime.Instantiate(allocCtx, binaryencoding.EncodeModule(&wasm.Module{
				TypeSection: []wasm.FunctionType{{Results: []wasm.ValueType{wasm.ValueTypeI32}}, {}},
				ImportSection: []wasm.Import{{
					Module: "owner", Name: "table", Type: wasm.ExternTypeTable, DescTable: wasm.Table{Type: wasm.RefTypeFuncref, Min: 1},
				}},
				ImportTableCount: 1,
				MemorySection:    &wasm.Memory{Min: 1},
				FunctionSection:  []wasm.Index{0, 1},
				ElementSection: []wasm.ElementSegment{{
					Type: wasm.RefTypeFuncref, Mode: wasm.ElementModeActive,
					OffsetExpr: wasm.NewConstantExpressionFromI32(0),
					Init:       []wasm.ConstantExpression{wasm.NewConstantExpressionFromOpcode(wasm.OpcodeRefFunc, []byte{0})},
				}},
				DataSection: []wasm.DataSegment{{OffsetExpression: wasm.NewConstantExpressionFromI32(0), Init: []byte{17}}},
				CodeSection: []wasm.Code{
					{Body: []byte{wasm.OpcodeI32Const, 0, wasm.OpcodeI32Load8U, 0, 0, wasm.OpcodeEnd}},
					{Body: []byte{wasm.OpcodeUnreachable, wasm.OpcodeEnd}},
				},
				StartSection: &start,
			}))
			require.Error(t, err)
			require.Equal(t, 0, allocation.frees, "the live table retains the failed instance")
			require.NoError(t, calleeRuntime.Close(ctx))
			result, err := owner.ExportedFunction("read").Call(ctx)
			require.NoError(t, err)
			require.Equal(t, []uint64{17}, result)
			require.NoError(t, owner.Close(ctx))
			require.Equal(t, 1, allocation.frees, "closing the last table user must collect the cycle")
		})
	}
}
