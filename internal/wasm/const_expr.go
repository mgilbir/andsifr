package wasm

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/mgilbir/andsifr/internal/leb128"
)

type ConstantExpression struct {
	Data []byte
}

func evaluateConstExpr(e *ConstantExpression, globalResolver func(globalIndex Index) (ValueType, uint64, uint64, error), funcRefResolver func(funcIndex Index) (Reference, error)) ([]uint64, ValueType, error) {
	var stack []uint64
	var typeStack []ValueType
	var pc uint64
	data := e.Data
	for {
		if pc >= uint64(len(data)) {
			return nil, 0, io.ErrUnexpectedEOF
		}
		opCode := data[pc]
		pc++
		switch opCode {
		case OpcodeI32Const:
			v, n, err := leb128.LoadInt32(data[pc:])
			if err != nil {
				return nil, 0, fmt.Errorf("read i32: %w", err)
			}
			pc += n
			stack = append(stack, uint64(uint32(v)))
			typeStack = append(typeStack, ValueTypeI32)
		case OpcodeI64Const:
			v, n, err := leb128.LoadInt64(data[pc:])
			if err != nil {
				return nil, 0, fmt.Errorf("read i64: %w", err)
			}
			pc += n
			stack = append(stack, uint64(v))
			typeStack = append(typeStack, ValueTypeI64)
		case OpcodeF32Const:
			if len(data[pc:]) < 4 {
				return nil, 0, io.ErrUnexpectedEOF
			}
			v := binary.LittleEndian.Uint32(data[pc:])
			pc += 4
			stack = append(stack, uint64(v))
			typeStack = append(typeStack, ValueTypeF32)
		case OpcodeF64Const:
			if len(data[pc:]) < 8 {
				return nil, 0, io.ErrUnexpectedEOF
			}
			v := binary.LittleEndian.Uint64(data[pc:])
			pc += 8
			stack = append(stack, uint64(v))
			typeStack = append(typeStack, ValueTypeF64)
		case OpcodeGlobalGet:
			v, n, err := leb128.LoadUint32(data[pc:])
			if err != nil {
				return nil, 0, fmt.Errorf("read index of global: %w", err)
			}
			pc += n
			typ, lo, hi, err := globalResolver(Index(v))
			if err != nil {
				return nil, 0, err
			}
			switch typ {
			case ValueTypeV128:
				stack = append(stack, lo, hi)
			default:
				stack = append(stack, lo)
			}
			typeStack = append(typeStack, typ)
		case OpcodeRefNull:
			// Reference types are opaque 64bit pointer at runtime.
			if pc >= uint64(len(data)) {
				return nil, 0, fmt.Errorf("read reference type for ref.null: %w", io.ErrShortBuffer)
			}
			b := data[pc]
			var valType ValueType
			switch b {
			case RefTypeFuncref.Kind():
				valType = RefTypeFuncref
				pc++
			case RefTypeExternref.Kind():
				valType = RefTypeExternref
				pc++
			case ValueTypeExnref.Kind():
				valType = ValueTypeExnref
				pc++
			default:
				// Concrete type index encoded as LEB128.
				typeIdx, n, err := leb128.LoadUint32(data[pc:])
				if err != nil {
					return nil, 0, fmt.Errorf("invalid type for ref.null: 0x%x", b)
				}
				pc += n
				valType = ValueTypeConcreteRef(typeIdx, true)
			}
			stack = append(stack, 0)
			typeStack = append(typeStack, valType)
		case OpcodeRefFunc:
			v, n, err := leb128.LoadUint32(data[pc:])
			if err != nil {
				return nil, 0, fmt.Errorf("read i32: %w", err)
			}
			pc += n
			ref, err := funcRefResolver(Index(v))
			if err != nil {
				return nil, 0, err
			}
			stack = append(stack, uint64(ref))
			typeStack = append(typeStack, ValueTypeFuncref)
		case OpcodeVecPrefix:
			if data[pc] != OpcodeVecV128Const {
				return nil, 0, fmt.Errorf("invalid vector opcode for const expression: %#x", data[pc-1])
			}
			pc++
			if len(data[pc:]) < 16 {
				return nil, 0, fmt.Errorf("%s needs 16 bytes but was %d bytes", OpcodeVecV128ConstName, len(data[pc:]))
			}
			lo := binary.LittleEndian.Uint64(data[pc:])
			pc += 8
			hi := binary.LittleEndian.Uint64(data[pc:])
			pc += 8
			stack = append(stack, lo, hi)
			typeStack = append(typeStack, ValueTypeV128)
		case OpcodeI32Add:
			if len(typeStack) < 2 {
				return nil, 0, errors.New("stack underflow on i32.add")
			}
			v1 := typeStack[len(typeStack)-1]
			v2 := typeStack[len(typeStack)-2]
			if v1 != ValueTypeI32 || v2 != ValueTypeI32 {
				return nil, 0, fmt.Errorf("type mismatch on i32.add: %s, %s", ValueTypeName(v2), ValueTypeName(v1))
			}
			b, a := stack[len(stack)-1], stack[len(stack)-2]
			stack = stack[:len(stack)-2]
			stack = append(stack, uint64(uint32(a)+uint32(b)))
			typeStack = typeStack[:len(typeStack)-2]
			typeStack = append(typeStack, ValueTypeI32)
		case OpcodeI32Sub:
			if len(typeStack) < 2 {
				return nil, 0, errors.New("stack underflow on i32.sub")
			}
			v1 := typeStack[len(typeStack)-1]
			v2 := typeStack[len(typeStack)-2]
			if v1 != ValueTypeI32 || v2 != ValueTypeI32 {
				return nil, 0, fmt.Errorf("type mismatch on i32.sub: %s, %s", ValueTypeName(v2), ValueTypeName(v1))
			}
			b, a := stack[len(stack)-1], stack[len(stack)-2]
			stack = stack[:len(stack)-2]
			stack = append(stack, uint64(uint32(a)-uint32(b)))
			typeStack = typeStack[:len(typeStack)-2]
			typeStack = append(typeStack, ValueTypeI32)
		case OpcodeI32Mul:
			if len(typeStack) < 2 {
				return nil, 0, errors.New("stack underflow on i32.mul")
			}
			v1 := typeStack[len(typeStack)-1]
			v2 := typeStack[len(typeStack)-2]
			if v1 != ValueTypeI32 || v2 != ValueTypeI32 {
				return nil, 0, fmt.Errorf("type mismatch on i32.mul: %s, %s", ValueTypeName(v2), ValueTypeName(v1))
			}
			b, a := stack[len(stack)-1], stack[len(stack)-2]
			stack = stack[:len(stack)-2]
			stack = append(stack, uint64(uint32(a)*uint32(b)))
			typeStack = typeStack[:len(typeStack)-2]
			typeStack = append(typeStack, ValueTypeI32)
		case OpcodeI64Add:
			if len(typeStack) < 2 {
				return nil, 0, errors.New("stack underflow on i64.add")
			}
			v1 := typeStack[len(typeStack)-1]
			v2 := typeStack[len(typeStack)-2]
			if v1 != ValueTypeI64 || v2 != ValueTypeI64 {
				return nil, 0, fmt.Errorf("type mismatch on i64.add: %s, %s", ValueTypeName(v2), ValueTypeName(v1))
			}
			b, a := stack[len(stack)-1], stack[len(stack)-2]
			stack = stack[:len(stack)-2]
			stack = append(stack, a+b)
			typeStack = typeStack[:len(typeStack)-2]
			typeStack = append(typeStack, ValueTypeI64)
		case OpcodeI64Sub:
			if len(typeStack) < 2 {
				return nil, 0, errors.New("stack underflow on i64.sub")
			}
			v1 := typeStack[len(typeStack)-1]
			v2 := typeStack[len(typeStack)-2]
			if v1 != ValueTypeI64 || v2 != ValueTypeI64 {
				return nil, 0, fmt.Errorf("type mismatch on i64.sub: %s, %s", ValueTypeName(v2), ValueTypeName(v1))
			}
			b, a := stack[len(stack)-1], stack[len(stack)-2]
			stack = stack[:len(stack)-2]
			stack = append(stack, a-b)
			typeStack = typeStack[:len(typeStack)-2]
			typeStack = append(typeStack, ValueTypeI64)
		case OpcodeI64Mul:
			if len(typeStack) < 2 {
				return nil, 0, errors.New("stack underflow on i64.mul")
			}
			v1 := typeStack[len(typeStack)-1]
			v2 := typeStack[len(typeStack)-2]
			if v1 != ValueTypeI64 || v2 != ValueTypeI64 {
				return nil, 0, fmt.Errorf("type mismatch on i64.mul: %s, %s", ValueTypeName(v2), ValueTypeName(v1))
			}
			b, a := stack[len(stack)-1], stack[len(stack)-2]
			stack = stack[:len(stack)-2]
			stack = append(stack, a*b)
			typeStack = typeStack[:len(typeStack)-2]
			typeStack = append(typeStack, ValueTypeI64)
		case OpcodeEnd:
			if len(typeStack) != 1 {
				return nil, 0, errors.New("stack has more than one value at end of constant expression")
			}
			return stack, typeStack[0], nil
		default:
			return nil, 0, fmt.Errorf("invalid opcode for const expression: 0x%x", opCode)
		}
	}
}

// constExprReferencesGlobal reports whether the constant expression contains a
// global.get. It walks the opcodes advancing past their immediates but does not
// evaluate them: no arithmetic, no stack, and — crucially — no dereference of
// any global (so it cannot panic on an out-of-range global index the way a full
// evaluateConstExpr pass can).
//
// It is deliberately fail-safe: any opcode it does not recognize, or a
// truncated immediate, is reported as "references a global" so that callers
// which use this to decide whether an operation is import-environment-dependent
// stay conservative. It reports on ANY global.get, imported or module-local:
// under CoreFeaturesExtendedConst an expression may global.get a module-local
// global whose own initializer transitively global.gets an imported one, so a
// local-vs-imported distinction would not be sufficient to prove
// import-independence.
func constExprReferencesGlobal(e *ConstantExpression) bool {
	data := e.Data
	for pc := 0; pc < len(data); {
		op := data[pc]
		pc++
		switch op {
		case OpcodeGlobalGet:
			return true
		case OpcodeEnd:
			return false
		case OpcodeI32Const:
			_, n, err := leb128.LoadInt32(data[pc:])
			if err != nil {
				return true
			}
			pc += int(n)
		case OpcodeI64Const:
			_, n, err := leb128.LoadInt64(data[pc:])
			if err != nil {
				return true
			}
			pc += int(n)
		case OpcodeI32Add, OpcodeI32Sub, OpcodeI32Mul,
			OpcodeI64Add, OpcodeI64Sub, OpcodeI64Mul:
			// No immediate operands.
		default:
			// Any other opcode (float/vector/reference const forms, or an
			// unknown one) is not a valid integer offset expression component.
			// Fail safe.
			return true
		}
	}
	// Ran off the end without an explicit OpcodeEnd: malformed. Fail safe.
	return true
}

func evaluateConstExprInModuleInstance(e *ConstantExpression, m *ModuleInstance) []uint64 {
	v, _, _ := evaluateConstExpr(
		e,
		func(globalIndex Index) (ValueType, uint64, uint64, error) {
			g := m.Globals[globalIndex]
			return g.Type.ValType, g.Val, g.ValHi, nil
		},
		func(funcIndex Index) (Reference, error) {
			return m.Engine.FunctionInstanceReference(funcIndex), nil
		},
	)
	return v
}

func NewConstantExpressionFromOpcode(
	opcode byte, opData []byte,
) ConstantExpression {
	data := make([]byte, 0, 3+len(opData)) // 2 for opcode and optional vec prefix, 1 for end
	if opcode == OpcodeVecV128Const {
		data = append(data, OpcodeVecPrefix)
	}
	data = append(data, opcode)
	data = append(data, opData...)
	data = append(data, OpcodeEnd)
	return ConstantExpression{Data: data}
}

func NewConstantExpressionFromI32(val int32) ConstantExpression {
	return NewConstantExpressionFromOpcode(OpcodeI32Const, leb128.EncodeInt32(val))
}

func NewConstantExpressionFromI64(val int64) ConstantExpression {
	return NewConstantExpressionFromOpcode(OpcodeI64Const, leb128.EncodeInt64(val))
}
