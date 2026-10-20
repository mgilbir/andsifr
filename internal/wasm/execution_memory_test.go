package wasm

import (
	"sync"
	"sync/atomic"
	"testing"
)

// Free may call back into the runtime. A retirement must release its lock before
// invoking the allocator, including when the last guest call performs the free.
type reentrantExecutionMemory struct{ frees atomic.Int32 }

func (m *reentrantExecutionMemory) Reallocate(size uint64) []byte { return make([]byte, size) }
func (m *reentrantExecutionMemory) Free() {
	m.frees.Add(1)
	entry := &ModuleInstance{}
	if execution := entry.BeginExecution(); execution != nil {
		execution.EndExecution()
	}
}

func TestModuleInstanceRetireMemoryConcurrentEnd(t *testing.T) {
	for i := 0; i < 1000; i++ {
		allocation := &reentrantExecutionMemory{}
		owner := &ModuleInstance{MemoryInstance: &MemoryInstance{expBuffer: allocation}}
		owner.Closed.Store(exitCodeFlagResourceClosed)
		entry := &ModuleInstance{}
		execution := entry.BeginExecution()
		if execution == nil {
			t.Fatal("entry unexpectedly closed")
		}
		var wg sync.WaitGroup
		wg.Add(3)
		go func() { defer wg.Done(); owner.retireMemory() }()
		go func() { defer wg.Done(); owner.retireMemory() }()
		go func() { defer wg.Done(); execution.EndExecution() }()
		wg.Wait()
		if got := allocation.frees.Load(); got != 1 {
			t.Fatalf("iteration %d: Free called %d times, want 1", i, got)
		}
	}
}

func TestModuleInstanceRetainImportConcurrentClose(t *testing.T) {
	for i := 0; i < 1000; i++ {
		allocation := &reentrantExecutionMemory{}
		owner := &ModuleInstance{MemoryInstance: &MemoryInstance{expBuffer: allocation}}
		importer := &ModuleInstance{}
		var retained bool
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			retained = importer.retainImport(owner)
		}()
		go func() {
			defer wg.Done()
			owner.Closed.Store(exitCodeFlagResourceClosed)
			owner.retireMemory()
		}()
		wg.Wait()
		if retained && allocation.frees.Load() != 0 {
			t.Fatal("a live importer lost its dependency's memory")
		}
		importer.retireMemory()
		if got := allocation.frees.Load(); got != 1 {
			t.Fatalf("iteration %d: Free called %d times, want 1", i, got)
		}
	}
}

func TestExecutionEpochReclamation(t *testing.T) {
	t.Run("later calls do not extend a retirement", func(t *testing.T) {
		entry := &ModuleInstance{}
		earlier := entry.BeginExecution()
		allocation := &reentrantExecutionMemory{}
		owner := &ModuleInstance{MemoryInstance: &MemoryInstance{expBuffer: allocation}}
		owner.retireMemory()
		later := entry.BeginExecution()
		defer later.EndExecution()
		if allocation.frees.Load() != 0 {
			t.Fatal("allocation freed before the earlier call returned")
		}
		earlier.EndExecution()
		if allocation.frees.Load() != 1 {
			t.Fatal("a later call prolonged the earlier retirement")
		}
	})
	t.Run("retirement waits for all earlier epochs", func(t *testing.T) {
		entry := &ModuleInstance{}
		earlier := entry.BeginExecution()
		first := &reentrantExecutionMemory{}
		(&ModuleInstance{MemoryInstance: &MemoryInstance{expBuffer: first}}).retireMemory()
		later := entry.BeginExecution()
		second := &reentrantExecutionMemory{}
		(&ModuleInstance{MemoryInstance: &MemoryInstance{expBuffer: second}}).retireMemory()
		later.EndExecution()
		if first.frees.Load() != 0 || second.frees.Load() != 0 {
			t.Fatal("an earlier call can still access both retired allocations")
		}
		earlier.EndExecution()
		if first.frees.Load() != 1 || second.frees.Load() != 1 {
			t.Fatal("completed epochs did not release both allocations")
		}
	})
}
