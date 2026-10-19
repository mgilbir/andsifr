package adhoc

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	wazero "github.com/mgilbir/andsifr"
	"github.com/mgilbir/andsifr/experimental"
	"github.com/mgilbir/andsifr/internal/testing/binaryencoding"
	"github.com/mgilbir/andsifr/internal/testing/require"
	"github.com/mgilbir/andsifr/internal/wasm"
)

// trackedMemory fails the test if it is freed while the guest is still
// executing (audit finding C11: Close during execution freed the
// allocator-backed memory immediately, causing use-after-free in JIT code).
type trackedMemory struct {
	onFree func()
}

func (m *trackedMemory) Reallocate(size uint64) []byte {
	return make([]byte, size)
}

func (m *trackedMemory) Free() {
	m.onFree()
}

// TestE2E_close_during_execution_defers_free ensures that closing a module
// while guest code is executing does not free the allocator-backed memory
// until the execution completed (C11 in codebase-audit-2026-10-18.md).
func TestE2E_close_during_execution_defers_free(t *testing.T) {
	var (
		// guestDone is set when the guest function returned from the blocking
		// host call, i.e. the execution observed the close.
		guestDone atomic.Bool
		// freedDuringExecution is set by the allocator if Free ran before the
		// guest execution completed.
		freedDuringExecution atomic.Bool
		freed                = make(chan struct{})
		chClosed             = make(chan struct{})
		hostEntered          = make(chan struct{})
		freeOnce             atomic.Bool
	)

	allocator := experimental.MemoryAllocatorFunc(func(cap, max uint64) experimental.LinearMemory {
		return &trackedMemory{onFree: func() {
			if !freeOnce.CompareAndSwap(false, true) {
				return // Free must run exactly once.
			}
			if !guestDone.Load() {
				freedDuringExecution.Store(true)
			}
			close(freed)
		}}
	})

	ctx := experimental.WithMemoryAllocator(context.Background(), allocator)

	// Guest: (memory 1) (import "env" "wait") (func (export "run") (call 0))
	guestWasm := binaryencoding.EncodeModule(&wasm.Module{
		TypeSection:         []wasm.FunctionType{{}},
		ImportFunctionCount: 1,
		ImportSection: []wasm.Import{
			{Module: "env", Name: "wait", Type: wasm.ExternTypeFunc, DescFunc: 0},
		},
		MemorySection:   &wasm.Memory{Min: 1, Cap: 1},
		FunctionSection: []wasm.Index{0},
		ExportSection:   []wasm.Export{{Name: "run", Type: wasm.ExternTypeFunc, Index: 1}},
		CodeSection:     []wasm.Code{{Body: []byte{wasm.OpcodeCall, 0, wasm.OpcodeEnd}}},
	})

	r := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfig())
	defer r.Close(ctx)

	_, err := r.NewHostModuleBuilder("env").
		NewFunctionBuilder().WithFunc(func(context.Context) {
		close(hostEntered)
		<-chClosed // blocks until the concurrent Close has completed.
		guestDone.Store(true)
	}).Export("wait").Instantiate(ctx)
	require.NoError(t, err)

	mod, err := r.Instantiate(ctx, guestWasm)
	require.NoError(t, err)

	// Close the module while the guest execution is blocked in the host call.
	go func() {
		<-hostEntered
		_ = mod.Close(ctx)
		close(chClosed)
	}()

	run := mod.ExportedFunction("run")
	require.NotNil(t, run)

	done := make(chan struct{})
	var callErr error
	go func() {
		defer close(done)
		_, callErr = run.Call(ctx)
	}()

	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("guest call did not complete")
	}

	// The call may fail with an ExitError (the module was closed during the
	// call), but the memory must not have been freed under the guest.
	require.False(t, freedDuringExecution.Load(), "memory was freed while guest code was still executing")
	if callErr != nil {
		t.Logf("call error (expected: the module was closed during the call): %v", callErr)
	}

	// After the execution completed, the deferred free must have run.
	select {
	case <-freed:
	case <-time.After(5 * time.Second):
		t.Fatal("deferred free never ran after the execution completed")
	}
}
