package wasm

import (
	"testing"

	"github.com/mgilbir/andsifr/internal/testing/require"
)

// TestIsRefSubtypeOfConcreteRefs covers the concrete-reference rules of
// isRefSubtypeOf fixed for C12 in codebase-audit-2026-10-18.md: two concrete
// refs are only related when the referenced types are structurally equivalent
// (at possibly different type section indexes), not merely by falling into the
// funcref-kind rule.
func TestIsRefSubtypeOfConcreteRefs(t *testing.T) {
	// $0: (i32)->(i32), $1: (i64)->(i64), $2: (i32)->(i32) (structurally
	// identical to $0 at a different index), $3/$4: mutually recursive
	// equivalents, $5/$6: non-equivalent recursive types.
	m := &Module{TypeSection: []FunctionType{
		{Params: []ValueType{ValueTypeI32}, Results: []ValueType{ValueTypeI32}}, // $0
		{Params: []ValueType{ValueTypeI64}, Results: []ValueType{ValueTypeI64}}, // $1
		{Params: []ValueType{ValueTypeI32}, Results: []ValueType{ValueTypeI32}}, // $2
		{Results: []ValueType{ValueTypeConcreteRef(3, false)}},                  // $3: (func (result (ref $3-4)))
		{Results: []ValueType{ValueTypeConcreteRef(4, false)}},                  // $4
		{Results: []ValueType{ValueTypeI32}},                                    // $5
		{Results: []ValueType{ValueTypeI64}},                                    // $6
	}}

	ref0 := ValueTypeConcreteRef(0, false) // (ref $0)
	ref1 := ValueTypeConcreteRef(1, false) // (ref $1)
	ref2 := ValueTypeConcreteRef(2, false) // (ref $2)
	ref3 := ValueTypeConcreteRef(3, false)
	ref4 := ValueTypeConcreteRef(4, false)
	ref5 := ValueTypeConcreteRef(5, false)
	ref6 := ValueTypeConcreteRef(6, false)
	nullRef0 := ValueTypeConcreteRef(0, true) // (ref null $0)
	nullRef1 := ValueTypeConcreteRef(1, true)

	t.Run("structurally unrelated concrete refs are unrelated", func(t *testing.T) {
		require.False(t, isRefSubtypeOf(m, ref0, ref1))
		require.False(t, isRefSubtypeOf(m, ref1, ref0))
		require.False(t, isRefSubtypeOf(m, nullRef1, ref0))
	})

	t.Run("structurally equivalent refs at different indexes are related", func(t *testing.T) {
		require.True(t, isRefSubtypeOf(m, ref0, ref2))
		require.True(t, isRefSubtypeOf(m, ref2, ref0))
		// Coinductive equivalence of mutually recursive types.
		require.True(t, isRefSubtypeOf(m, ref3, ref4))
		require.True(t, isRefSubtypeOf(m, ref4, ref3))
		// Non-equivalent recursive types stay unrelated.
		require.False(t, isRefSubtypeOf(m, ref5, ref6))
	})

	t.Run("nullability direction", func(t *testing.T) {
		// (ref $0) <: (ref null $0)
		require.True(t, isRefSubtypeOf(m, ref0, nullRef0))
		// (ref null $0) is not <: (ref $0)
		require.False(t, isRefSubtypeOf(m, nullRef0, ref0))
		// (ref null $0) <: (ref null $2) by structural equivalence.
		require.True(t, isRefSubtypeOf(m, nullRef0, ValueTypeConcreteRef(2, true)))
		// (ref null $0) is not <: (ref $2).
		require.False(t, isRefSubtypeOf(m, nullRef0, ref2))
	})

	t.Run("concrete ref vs abstract funcref", func(t *testing.T) {
		// (ref $0) <: funcref and <: (ref func)
		require.True(t, isRefSubtypeOf(m, ref0, ValueTypeFuncref))
		require.True(t, isRefSubtypeOf(m, ref0, ValueTypeFuncref.AsNonNullable()))
		// (ref null $0) <: funcref (nullable) but not <: (ref func)
		require.True(t, isRefSubtypeOf(m, nullRef0, ValueTypeFuncref))
		require.False(t, isRefSubtypeOf(m, nullRef0, ValueTypeFuncref.AsNonNullable()))
		// Abstract funcref is never a subtype of a concrete ref.
		require.False(t, isRefSubtypeOf(m, ValueTypeFuncref, ref0))
		require.False(t, isRefSubtypeOf(m, ValueTypeFuncref, nullRef0))
	})
}
