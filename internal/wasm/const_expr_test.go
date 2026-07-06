package wasm

import (
	"testing"

	"github.com/mgilbir/andsifr/internal/testing/require"
)

func Test_constExprReferencesGlobal(t *testing.T) {
	for _, tc := range []struct {
		name string
		expr ConstantExpression
		want bool
	}{
		{
			name: "plain i32.const",
			expr: NewConstantExpressionFromI32(5),
			want: false,
		},
		{
			// i32.const 35 encodes as 0x41 0x23 0x0b: the immediate byte is 0x23,
			// which is also OpcodeGlobalGet. A naive byte scan would false-positive
			// here; the opcode walk must correctly skip the immediate and report
			// false so this segment can still take the (fast) skip path.
			name: "i32.const whose immediate byte is 0x23 (global.get)",
			expr: NewConstantExpressionFromI32(35),
			want: false,
		},
		{
			name: "plain i64.const",
			expr: NewConstantExpressionFromI64(1 << 40),
			want: false,
		},
		{
			name: "global.get",
			expr: NewConstantExpressionFromOpcode(OpcodeGlobalGet, []byte{0}),
			want: true,
		},
		{
			// extended-const: global.get 0; i32.const 8; i32.add; end
			name: "global.get nested in arithmetic",
			expr: ConstantExpression{Data: []byte{
				OpcodeGlobalGet, 0x00,
				OpcodeI32Const, 0x08,
				OpcodeI32Add,
				OpcodeEnd,
			}},
			want: true,
		},
		{
			// extended-const arithmetic with no global: i32.const 4; i32.const 8; i32.mul; end
			name: "arithmetic without a global",
			expr: ConstantExpression{Data: []byte{
				OpcodeI32Const, 0x04,
				OpcodeI32Const, 0x08,
				OpcodeI32Mul,
				OpcodeEnd,
			}},
			want: false,
		},
		{
			// f64.const is a valid const opcode but never a valid i32/i64 offset;
			// the walk fails safe and refuses (reports a global dependence).
			name: "unsupported const form fails safe",
			expr: ConstantExpression{Data: append([]byte{OpcodeF64Const}, make([]byte, 8)...)},
			want: true,
		},
		{
			name: "truncated immediate fails safe",
			expr: ConstantExpression{Data: []byte{OpcodeI32Const}},
			want: true,
		},
		{
			name: "missing end fails safe",
			expr: ConstantExpression{Data: []byte{OpcodeI32Const, 0x05}},
			want: true,
		},
		{
			name: "empty expression fails safe",
			expr: ConstantExpression{Data: nil},
			want: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, constExprReferencesGlobal(&tc.expr))
		})
	}
}
