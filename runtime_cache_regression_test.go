package wazero_test

import (
	"context"
	"sync"
	"testing"

	wazero "github.com/mgilbir/andsifr"
	"github.com/mgilbir/andsifr/api"
	"github.com/mgilbir/andsifr/experimental"
	"github.com/mgilbir/andsifr/internal/platform"
	"github.com/mgilbir/andsifr/internal/testing/binaryencoding"
	"github.com/mgilbir/andsifr/internal/wasm"
)

//go:noinline
func newClosureListenerFactory(counter *int) experimental.FunctionListenerFactory {
	return experimental.FunctionListenerFactoryFunc(func(api.FunctionDefinition) experimental.FunctionListener {
		return experimental.FunctionListenerFunc(func(context.Context, api.Module, api.FunctionDefinition, []uint64, experimental.StackIterator) {
			*counter++
		})
	})
}

type valueListenerFactory struct {
	factory experimental.FunctionListenerFactory
}

func (f valueListenerFactory) NewFunctionListener(def api.FunctionDefinition) experimental.FunctionListener {
	return f.factory.NewFunctionListener(def)
}

func TestListenerFactoryClosureIdentity(t *testing.T) {
	configs := []wazero.RuntimeConfig{wazero.NewRuntimeConfigInterpreter()}
	if platform.CompilerSupported() {
		configs = append(configs, wazero.NewRuntimeConfigCompiler())
	}
	for _, config := range configs {
		for _, valueFactory := range []bool{false, true} {
			testListenerFactoryIdentity(t, config, valueFactory)
		}
	}
}

func testListenerFactoryIdentity(t *testing.T, config wazero.RuntimeConfig, valueFactory bool) {
	t.Helper()
	ctx := context.Background()
	r := wazero.NewRuntimeWithConfig(ctx, config)
	defer r.Close(ctx)
	bin := binaryencoding.EncodeModule(&wasm.Module{TypeSection: []wasm.FunctionType{{}}, FunctionSection: []wasm.Index{0}, ExportSection: []wasm.Export{{Name: "f", Type: wasm.ExternTypeFunc, Index: 0}}, CodeSection: []wasm.Code{{Body: []byte{wasm.OpcodeEnd}}}})
	var first, second int
	for _, factory := range []experimental.FunctionListenerFactory{newClosureListenerFactory(&first), newClosureListenerFactory(&second)} {
		if valueFactory {
			factory = valueListenerFactory{factory: factory}
		}
		compileCtx := experimental.WithFunctionListenerFactory(ctx, factory)
		for repeat := 0; repeat < 2; repeat++ {
			code, err := r.CompileModule(compileCtx, bin)
			if err != nil {
				t.Fatal(err)
			}
			mod, err := r.InstantiateModule(ctx, code, wazero.NewModuleConfig().WithName(""))
			if err != nil {
				t.Fatal(err)
			}
			_, err = mod.ExportedFunction("f").Call(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if err := mod.Close(ctx); err != nil {
				t.Fatal(err)
			}
			defer code.Close(ctx)
		}
	}
	if first != 2 || second != 2 {
		t.Errorf("wrong listener: first=%d second=%d", first, second)
	}
}

func TestCompilationCacheConcurrentInitAndClose(t *testing.T) {
	ctx := context.Background()
	cache := wazero.NewCompilationCache()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			r := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfigInterpreter().WithCoreFeatures(api.CoreFeatures(i)).WithCompilationCache(cache))
			r.Close(ctx)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			cache.Close(ctx)
		}
	}()
	wg.Wait()
}
