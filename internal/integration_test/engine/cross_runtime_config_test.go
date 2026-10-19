package adhoc

import (
	"context"
	"strings"
	"testing"

	wazero "github.com/mgilbir/andsifr"
	"github.com/mgilbir/andsifr/api"
	"github.com/mgilbir/andsifr/internal/testing/binaryencoding"
	"github.com/mgilbir/andsifr/internal/testing/require"
	"github.com/mgilbir/andsifr/internal/wasm"
)

// TestE2E_cross_runtime_config_mismatch ensures that instantiating a
// CompiledModule in a second Runtime is refused when that Runtime's
// configuration differs in ways that were baked in at compile time and cannot
// be re-applied (WithMemoryLimitPages, WithCoreFeatures,
// WithCloseOnContextDone). Previously the second Runtime's settings were
// silently ignored (C9 in codebase-audit-2026-10-18.md).
func TestE2E_cross_runtime_config_mismatch(t *testing.T) {
	ctx := context.Background()
	wasmBin := binaryencoding.EncodeModule(&wasm.Module{
		TypeSection:     []wasm.FunctionType{{}},
		FunctionSection: []wasm.Index{0},
		CodeSection:     []wasm.Code{{Body: []byte{wasm.OpcodeEnd}}},
	})

	compile := func(config wazero.RuntimeConfig) wazero.CompiledModule {
		r := wazero.NewRuntimeWithConfig(ctx, config)
		t.Cleanup(func() { _ = r.Close(ctx) })
		c, err := r.CompileModule(ctx, wasmBin)
		require.NoError(t, err)
		return c
	}

	// Cross-Runtime instantiation is only supported with a shared cache.
	sharedCache := wazero.NewCompilationCache()
	withCache := func(c wazero.RuntimeConfig) wazero.RuntimeConfig {
		return c.WithCompilationCache(sharedCache)
	}

	t.Run("identical config instantiates", func(t *testing.T) {
		code := compile(withCache(wazero.NewRuntimeConfig()))
		r2 := wazero.NewRuntimeWithConfig(ctx, withCache(wazero.NewRuntimeConfig()))
		defer r2.Close(ctx)
		_, err := r2.InstantiateModule(ctx, code, wazero.NewModuleConfig())
		require.NoError(t, err)
	})

	t.Run("memory limit pages mismatch is refused", func(t *testing.T) {
		code := compile(wazero.NewRuntimeConfig())
		r2 := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfig().WithMemoryLimitPages(17))
		defer r2.Close(ctx)
		_, err := r2.InstantiateModule(ctx, code, wazero.NewModuleConfig())
		require.Error(t, err)
		require.True(t, strings.Contains(err.Error(), "WithMemoryLimitPages"))
	})

	t.Run("core features mismatch is refused", func(t *testing.T) {
		code := compile(wazero.NewRuntimeConfig())
		r2 := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfig().WithCoreFeatures(api.CoreFeaturesV1))
		defer r2.Close(ctx)
		_, err := r2.InstantiateModule(ctx, code, wazero.NewModuleConfig())
		require.Error(t, err)
		require.True(t, strings.Contains(err.Error(), "core features"))
	})

	t.Run("close on context done mismatch is refused", func(t *testing.T) {
		code := compile(wazero.NewRuntimeConfig())
		r2 := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfig().WithCloseOnContextDone(true))
		defer r2.Close(ctx)
		_, err := r2.InstantiateModule(ctx, code, wazero.NewModuleConfig())
		require.Error(t, err)
		require.True(t, strings.Contains(err.Error(), "WithCloseOnContextDone"))
	})
}
