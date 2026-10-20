package experimental

import (
	"context"

	"github.com/mgilbir/andsifr/internal/expctxkeys"
)

// MemoryAllocator is a memory allocation hook,
// invoked to create a LinearMemory.
type MemoryAllocator interface {
	// Allocate should create a new LinearMemory with the given specification:
	// cap is the suggested initial capacity for the backing []byte,
	// and max the maximum length that will ever be requested.
	//
	// Notes:
	//   - To back a shared memory, the address of the backing []byte cannot
	//     change. This is checked at runtime. Implementations should document
	//     if the returned LinearMemory meets this requirement.
	Allocate(cap, max uint64) LinearMemory
}

// MemoryAllocatorFunc is a convenience for defining inlining a MemoryAllocator.
type MemoryAllocatorFunc func(cap, max uint64) LinearMemory

// Allocate implements MemoryAllocator.Allocate.
func (f MemoryAllocatorFunc) Allocate(cap, max uint64) LinearMemory {
	return f(cap, max)
}

// LinearMemory is an expandable []byte that backs a Wasm linear memory.
type LinearMemory interface {
	// Reallocates the linear memory to size bytes in length.
	//
	// Notes:
	//   - To back a shared memory, Reallocate can't change the address of the
	//     backing []byte (only its length/capacity may change).
	//   - Reallocate may return nil if fails to grow the LinearMemory. This
	//     condition may or may not be handled gracefully by the Wasm module.
	Reallocate(size uint64) []byte
	// Free releases the backing memory buffer. Closing the owning module defers
	// Free until modules that can reach it through imports or shared tables have
	// closed and guest calls already in flight at retirement have returned. Calls
	// in other modules or runtimes may also delay Free, since function references can
	// cross those boundaries. Calls started after retirement do not prolong it.
	Free()
}

// MemoryWithPreappliedData is an optional interface a LinearMemory may
// implement to declare that its initial contents already include the active
// data segments of a specific module — for example a copy-on-write view of
// the memory of a previously initialized instance of that module. When it
// returns true, instantiation skips copying active data segments into the
// memory; active-segment bounds are still validated and passive data
// instances are still registered.
//
// The moduleID passed to PreappliedDataFor is the SHA-256 of the module's
// binary (the same identity the compilation cache is keyed on).
// Implementations must record the ID of the module whose post-initialization
// memory the image was built from, and return true only for that exact ID, so
// that an image can never be applied to a different (e.g. updated) module.
// When the runtime refuses the skip for newly allocated memory (mismatched ID,
// a start section, or an active data offset depending on an imported global), it
// clears the returned buffer before copying the active data segments: a refused
// image must not leak any of its contents into the instance. Imported memory
// always receives the importing module's active data segments normally, without
// clearing existing contents outside those segments.
//
// The skip is additionally refused by the runtime when any active data
// segment offset depends on an imported global, since then the segment
// placement is not determined by the module identity alone.
//
// A mismatched image changes guest semantics but does not affect isolation
// between instances, since the contents come only from the host-provided
// image. Shared memories are not supported.
type MemoryWithPreappliedData interface {
	// PreappliedDataFor reports whether the memory returned by Reallocate
	// already contains the active data segments of the module identified by
	// moduleID (SHA-256 of the module binary).
	PreappliedDataFor(moduleID [32]byte) bool
}

// WithMemoryAllocator registers the given MemoryAllocator into the given
// context.Context. The context must be passed when initializing a module.
func WithMemoryAllocator(ctx context.Context, allocator MemoryAllocator) context.Context {
	if allocator != nil {
		return context.WithValue(ctx, expctxkeys.MemoryAllocatorKey{}, allocator)
	}
	return ctx
}
