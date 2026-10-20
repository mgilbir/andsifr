package wasm

import (
	"sync"
	"sync/atomic"

	"github.com/mgilbir/andsifr/experimental"
)

// guestExecutions guards allocator-backed memory across all guest entry calls.
// Imports and function references can cross module and store boundaries without
// entering Go again, so a per-entry-module counter cannot protect their memory.
// Closing a module retires its allocation until calls already in flight return.
// New calls join a new epoch, so continuous traffic cannot postpone Free forever.
var guestExecutions struct {
	sync.Mutex
	current atomic.Pointer[executionEpoch]
	head    *executionEpoch
	tail    *executionEpoch
}

type executionEpoch struct {
	active atomic.Int64
	// next and retired are guarded by guestExecutions.Mutex. Only sealed
	// epochs are queued; a retired allocation waits for every earlier epoch.
	next    *executionEpoch
	retired []retiredMemory
}

type retiredMemory struct {
	memory     *MemoryInstance
	allocation experimental.LinearMemory
}

// BeginExecution pins an epoch before entering guest code. A nil return means
// the entry module is closed. Otherwise the caller must defer EndExecution on
// the returned epoch, including when guest code traps or panics.
func (m *ModuleInstance) BeginExecution() *executionEpoch {
	for {
		epoch := guestExecutions.current.Load()
		if epoch == nil {
			guestExecutions.current.CompareAndSwap(nil, &executionEpoch{})
			continue
		}
		epoch.active.Add(1)
		// A concurrent retirement may have sealed this epoch before we pinned
		// it. Do not enter guest code until the pin is confirmed current.
		if epoch != guestExecutions.current.Load() {
			epoch.EndExecution()
			continue
		}
		if m.Closed.Load() != 0 {
			epoch.EndExecution()
			return nil
		}
		return epoch
	}
}

// EndExecution releases allocations retired while guest code was in flight.
func (e *executionEpoch) EndExecution() {
	// Only a sealed epoch can have retired allocations. A concurrent retire
	// either observes this decrement when collecting, or seals the epoch before
	// the current-pointer check and leaves collection to us.
	if e.active.Add(-1) != 0 || e == guestExecutions.current.Load() {
		return
	}
	guestExecutions.Lock()
	retired := collectRetiredMemory()
	guestExecutions.Unlock()
	// Allocator callbacks may reenter the runtime: never invoke them under a lock.
	for _, entry := range retired {
		entry.allocation.Free()
	}
}

// collectRetiredMemory drains completed epochs in order. Later epochs may
// finish first, but their allocations can still be in use by earlier calls.
// The caller holds guestExecutions.Mutex and invokes Free outside the lock.
func collectRetiredMemory() (retired []retiredMemory) {
	for epoch := guestExecutions.head; epoch != nil && epoch.active.Load() == 0; epoch = guestExecutions.head {
		retired = append(retired, epoch.retired...)
		guestExecutions.head = epoch.next
		epoch.next, epoch.retired = nil, nil
	}
	if guestExecutions.head == nil {
		guestExecutions.tail = nil
	}
	for _, entry := range retired {
		entry.memory.expBuffer = nil
	}
	return
}

// retainImport pins the dependency before its exports are accessed. Close can
// race with linking: the check and the reference acquisition must be atomic
// with respect to retiring the dependency's allocation.
func (m *ModuleInstance) retainImport(imported *ModuleInstance) bool {
	guestExecutions.Lock()
	defer guestExecutions.Unlock()
	if imported.IsClosed() || imported.memoryClosed {
		return false
	}
	if imported.importers == nil {
		imported.importers = map[*ModuleInstance]uint32{}
	}
	imported.importers[m]++
	m.importedModules = append(m.importedModules, imported)
	return true
}

// unreferencedClosedModules returns the closed modules that retain m, provided
// none is reachable from a live importer. Traversing reverse edges also handles
// cycles caused by shared tables. The usual case, with no importers, allocates
// no visited map. The caller holds guestExecutions.Mutex.
func (m *ModuleInstance) unreferencedClosedModules() []*ModuleInstance {
	if len(m.importers) == 0 {
		return []*ModuleInstance{m}
	}
	seen := map[*ModuleInstance]bool{m: true}
	modules := []*ModuleInstance{m}
	for i := 0; i < len(modules); i++ {
		for importer := range modules[i].importers {
			if !importer.memoryClosed {
				return nil
			}
			if !seen[importer] {
				seen[importer] = true
				modules = append(modules, importer)
			}
		}
	}
	return modules
}

// retireMemory releases allocations and import references once the module is
// closed and no live importer depends on it. In-flight guest calls may still
// access the allocation, so the final Free waits for them to return.
func (m *ModuleInstance) retireMemory() {
	guestExecutions.Lock()
	if m.memoryClosed {
		guestExecutions.Unlock()
		return
	}
	m.memoryClosed = true
	ready := []*ModuleInstance{m}
	var retired []retiredMemory
	for len(ready) > 0 {
		last := len(ready) - 1
		module := ready[last]
		ready = ready[:last]
		if !module.memoryClosed || module.memoryReleased {
			continue
		}
		modules := module.unreferencedClosedModules()
		for _, closed := range modules {
			closed.memoryReleased = true
		}
		for _, closed := range modules {
			for _, imported := range closed.importedModules {
				if imported.importers[closed]--; imported.importers[closed] == 0 {
					delete(imported.importers, closed)
				}
				ready = append(ready, imported)
			}
			closed.importedModules = nil
			mem := closed.MemoryInstance
			if mem == nil || mem.ownerModuleEngine != closed.Engine || mem.expBuffer == nil {
				continue
			}
			retired = append(retired, retiredMemory{memory: mem, allocation: mem.expBuffer})
		}
	}
	if len(retired) > 0 {
		// Swap while holding the retirement lock, then seal the old epoch.
		// Calls that pinned it before the swap protect this batch; subsequent
		// callers retry in the new epoch before touching guest memory.
		epoch := guestExecutions.current.Swap(&executionEpoch{})
		if epoch == nil {
			epoch = &executionEpoch{}
		}
		epoch.retired = retired
		if guestExecutions.tail == nil {
			guestExecutions.head = epoch
		} else {
			guestExecutions.tail.next = epoch
		}
		guestExecutions.tail = epoch
		retired = collectRetiredMemory()
	}
	guestExecutions.Unlock()
	for _, entry := range retired {
		entry.allocation.Free()
	}
}
