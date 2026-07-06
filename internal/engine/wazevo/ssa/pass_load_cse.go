package ssa

// This file implements passRedundantLoadEliminationOpt, an intra-block
// redundant-load elimination and store-to-load forwarding pass.

// loadCSEKey identifies a memory access within a basic block for the purpose of
// load reuse: the root of the (alias-resolved) base pointer value after peeling
// constant Iadds, the accumulated static offset, the result type and the load
// opcode (which encodes the access width and extension behavior).
type loadCSEKey struct {
	root   ValueID
	offset uint64
	typ    Type
	op     Opcode
}

// loadCSEEntry is the cached result of a load (or a stored value being
// forwarded), together with the byte footprint of the access used for overlap
// checks against later stores.
type loadCSEEntry struct {
	v           Value
	sizeInBytes uint32
}

// passRedundantLoadEliminationOpt eliminates, within each basic block, loads
// that are provably redundant: a load from the same base pointer, offset and
// width as a previous load (or full-width store) with no potentially
// overlapping store, call, or atomic operation in between is aliased to the
// previous value, and later removed by the dead-code elimination pass.
//
// Base pointers are decomposed into (root, static offset) by peeling constant
// Iadds, so that e.g. `memoryBase + 0x1000` and `memoryBase + 0x2000` are
// recognized as offsets from the same root. The alias analysis is otherwise
// intentionally conservative:
//   - two accesses with different roots are assumed to potentially overlap;
//     with the same root, the signed distance between their static offsets
//     decides overlap exactly (the runtime addresses differ by exactly that
//     distance);
//   - calls (including the ones implementing memory.grow/copy/fill) invalidate
//     everything;
//   - atomic operations and fences invalidate everything, since reusing an
//     earlier loaded value moves the read before the synchronization point.
func passRedundantLoadEliminationOpt(b *builder) {
	cache := make(map[loadCSEKey]loadCSEEntry)
	for blk := b.blockIteratorBegin(); blk != nil; blk = b.blockIteratorNext() {
		clear(cache)
		for cur := blk.rootInstr; cur != nil; cur = cur.next {
			switch op := cur.Opcode(); op {
			case OpcodeLoad, OpcodeUload8, OpcodeUload16, OpcodeUload32, OpcodeSload8, OpcodeSload16, OpcodeSload32:
				ptr, offset, typ := cur.LoadData()
				root, staticOff := b.decomposePointer(ptr)
				key := loadCSEKey{root: root, offset: staticOff + uint64(offset), typ: typ, op: op}
				if prev, ok := cache[key]; ok {
					b.alias(cur.Return(), prev.v)
				} else {
					cache[key] = loadCSEEntry{v: cur.Return(), sizeInBytes: loadAccessSizeInBytes(op, typ)}
				}
			case OpcodeStore, OpcodeIstore8, OpcodeIstore16, OpcodeIstore32:
				value, ptr, offset, storeSizeInBits := cur.StoreData()
				storeSize := uint32(storeSizeInBits) / 8
				root, staticOff := b.decomposePointer(ptr)
				storeOff := staticOff + uint64(offset)
				for k, e := range cache {
					if k.root != root || rangesOverlap(k.offset, e.sizeInBytes, storeOff, storeSize) {
						delete(cache, k)
					}
				}
				if op == OpcodeStore {
					// A full-width store makes the stored value available to
					// subsequent same-typed loads from the same address.
					cache[loadCSEKey{root: root, offset: storeOff, typ: value.Type(), op: OpcodeLoad}] = loadCSEEntry{v: value, sizeInBytes: storeSize}
				}
			case OpcodeCall, OpcodeCallIndirect,
				OpcodeAtomicRmw, OpcodeAtomicCas, OpcodeAtomicLoad, OpcodeAtomicStore, OpcodeFence:
				clear(cache)
			}
		}
	}
}

// decomposePointer resolves aliases and peels constant 64-bit Iadds off the
// given pointer value, returning the root value ID and the accumulated static
// offset (with wrap-around semantics, matching the runtime address arithmetic).
func (b *builder) decomposePointer(ptr Value) (root ValueID, offset uint64) {
	v := b.resolveAlias(ptr)
	for {
		def := b.InstructionOfValue(v)
		if def == nil || def.Opcode() != OpcodeIadd || v.Type() != TypeI64 {
			break
		}
		x, y := def.Arg2()
		x, y = b.resolveAlias(x), b.resolveAlias(y)
		if xDef := b.InstructionOfValue(x); xDef != nil && xDef.Constant() {
			offset += xDef.ConstantVal()
			v = y
		} else if yDef := b.InstructionOfValue(y); yDef != nil && yDef.Constant() {
			offset += yDef.ConstantVal()
			v = x
		} else {
			break
		}
	}
	return v.ID(), offset
}

// loadAccessSizeInBytes returns the number of bytes read by the given load opcode.
func loadAccessSizeInBytes(op Opcode, typ Type) uint32 {
	switch op {
	case OpcodeUload8, OpcodeSload8:
		return 1
	case OpcodeUload16, OpcodeSload16:
		return 2
	case OpcodeUload32, OpcodeSload32:
		return 4
	default:
		return uint32(typ.Bits()) / 8
	}
}

// rangesOverlap returns true if [aOff, aOff+aSize) and [bOff, bOff+bSize)
// intersect. Offsets are compared through their signed difference, which is
// exact under the wrap-around address arithmetic as long as the two accesses
// are less than 2^63 bytes apart (always true for accesses within the same
// linear memory or host structure).
func rangesOverlap(aOff uint64, aSize uint32, bOff uint64, bSize uint32) bool {
	d := int64(aOff - bOff)
	return -int64(aSize) < d && d < int64(bSize)
}
