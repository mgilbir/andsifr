package binaryencoding

import (
	"bytes"
	"fmt"

	"github.com/mgilbir/andsifr/internal/leb128"
	"github.com/mgilbir/andsifr/internal/wasm"
)

func ensureElementKindFuncRef(r *bytes.Reader) error {
	elemKind, err := r.ReadByte()
	if err != nil {
		return fmt.Errorf("read element prefix: %w", err)
	}
	if elemKind != 0x0 { // ElemKind is fixed to 0x0 now: https://www.w3.org/TR/2022/WD-wasm-core-2-20220419/binary/modules.html#element-section
		return fmt.Errorf("element kind must be zero but was 0x%x", elemKind)
	}
	return nil
}

// encodeCode returns the wasm.ElementSegment encoded in WebAssembly 1.0 (20191205) Binary Format.
//
// https://www.w3.org/TR/2019/REC-wasm-core-1-20191205/#element-section%E2%91%A0
func encodeElement(e *wasm.ElementSegment) (ret []byte) {
	if e.Mode == wasm.ElementModeActive {
		// A zero Type means the fixture did not care: default to funcref
		// (the legacy encoding implies it).
		if e.Type != wasm.RefTypeFuncref && e.Type != 0 {
			// Modern encoding, prefix 6: tableidx, offset expr, reftype,
			// vec(const_expr) -- the only way to express a typed active
			// element segment.
			ret = append(ret, leb128.EncodeUint32(6)...)
			ret = append(ret, leb128.EncodeUint32(uint32(e.TableIndex))...)
			ret = append(ret, encodeConstantExpression(e.OffsetExpr)...)
			ret = append(ret, EncodeValueType(e.Type)...)
			ret = append(ret, leb128.EncodeUint32(uint32(len(e.Init)))...)
			for _, expr := range e.Init {
				ret = append(ret, expr.Data...)
			}
			return ret
		}
		if e.TableIndex != 0 {
			// Modern encoding, prefix 2: tableidx, elemkind, offset expr,
			// vec(funcidx). The previous encoder wrote the table index into
			// the flags position, mis-encoding any non-zero table index.
			ret = append(ret, leb128.EncodeUint32(2)...)
			ret = append(ret, leb128.EncodeUint32(uint32(e.TableIndex))...)
			ret = append(ret, 0x00) // elemkind: funcref
		} else {
			// Legacy encoding, prefix 0: table 0 implied.
			ret = append(ret, 0x00)
		}
		ret = append(ret, encodeConstantExpression(e.OffsetExpr)...)
		ret = append(ret, leb128.EncodeUint32(uint32(len(e.Init)))...)
		for _, expr := range e.Init {
			if expr.Data[0] == wasm.OpcodeRefFunc {
				u32, n, _ := leb128.DecodeUint32(bytes.NewReader(expr.Data[1:]))
				ind := uint32(u32)
				ret = append(ret, leb128.EncodeUint32(ind)...)
				if expr.Data[1+n] != wasm.OpcodeEnd {
					panic("only single op ref.func is supported for active element encoding")
				}
			} else {
				panic("only ref.func is supported for active element encoding")
			}
		}
	} else {
		panic("TODO: support encoding for non-active elements in bulk-memory-operations proposal")
	}
	return
}
