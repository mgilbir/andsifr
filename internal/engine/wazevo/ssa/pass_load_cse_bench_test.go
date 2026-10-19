package ssa

import "testing"

// BenchmarkPassLoadCSE_manyStores measures the store-heavy pathological case
// from C31: 80k stores in one block.
func BenchmarkPassLoadCSE_manyStores(b *testing.B) {
	for i := 0; i < b.N; i++ {
		builder := NewBuilder().(*builder)
		entry := builder.AllocateBasicBlock()
		builder.SetCurrentBlock(entry)
		base := entry.AddParam(builder, TypeI64)
		val := entry.AddParam(builder, TypeI64)
		for j := 0; j < 80000; j++ {
			st := builder.AllocateInstruction()
			st.AsStore(OpcodeStore, val, base, 8)
			builder.InsertInstruction(st)
		}
		ret := builder.AllocateInstruction()
		ret.AsReturn(ValuesNil)
		builder.InsertInstruction(ret)
		passRedundantLoadEliminationOpt(builder)
	}
}
