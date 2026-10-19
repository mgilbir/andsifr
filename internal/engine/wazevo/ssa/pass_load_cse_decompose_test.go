package ssa

import (
	"testing"
)

// TestDecomposePointerUextend ensures the load-CSE pointer decomposition sees
// through UExtend of a constant i32 index, so wasm memory accesses at constant
// offsets share a root (C70).
func TestDecomposePointerUextend(t *testing.T) {
	b := NewBuilder().(*builder)
	entry := b.AllocateBasicBlock()
	b.SetCurrentBlock(entry)
	memoryBase := entry.AddParam(b, TypeI64)

	iconst := b.AllocateInstruction()
	iconst.AsIconst32(0x1000)
	b.InsertInstruction(iconst)

	uextend := b.AllocateInstruction()
	uextend.AsUExtend(iconst.Return(), 32, 64)
	b.InsertInstruction(uextend)

	iadd := b.AllocateInstruction()
	iadd.AsIadd(memoryBase, uextend.Return())
	b.InsertInstruction(iadd)

	root, off := b.decomposePointer(iadd.Return())
	if root != memoryBase.ID() {
		t.Fatalf("root = %v, want memoryBase %v", root, memoryBase.ID())
	}
	if off != 0x1000 {
		t.Fatalf("offset = %#x, want 0x1000", off)
	}
}
