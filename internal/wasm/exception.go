package wasm

// Exception represents a thrown WebAssembly exception.
type Exception struct {
	// Tag is the tag instance that was thrown.
	Tag *TagInstance
	// Params holds the argument values matching the tag's function type params.
	Params []uint64
}

// ExceptionParamSlots returns the number of uint64 slots required to hold the
// given tag parameters in Exception.Params: one per scalar value and two per
// v128 value, stored slot-packed in parameter order. v128 params occupy two
// consecutive slots so a 16-byte store/load can be used (C14 in
// codebase-audit-2026-10-18.md: sizing the slice by parameter count overflowed
// the Go heap when a tag had a v128 parameter).
func ExceptionParamSlots(params []ValueType) int {
	slots := 0
	for _, p := range params {
		if p == ValueTypeV128 {
			slots += 2
		} else {
			slots++
		}
	}
	return slots
}
