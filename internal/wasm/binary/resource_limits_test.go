package binary

import (
	"bytes"
	"testing"

	"github.com/mgilbir/andsifr/api"
	"github.com/mgilbir/andsifr/internal/leb128"
	"github.com/mgilbir/andsifr/internal/testing/require"
	"github.com/mgilbir/andsifr/internal/wasm"
)

// These tests exercise the decoder's resource bounds: counts of elements or locals
// read from a malformed module must not drive enormous allocations before the
// remaining input bytes are checked (codebase-audit-2026-10-18.md C3).

// u32 returns the unsigned LEB128 encoding of v.
func u32(v uint32) []byte {
	return leb128.EncodeUint32(v)
}

func TestDecodeModule_ExcessiveLocalsRejected(t *testing.T) {
	// A 30-byte-ish module whose single function declares 2^32-1 locals.
	// Before the fix, this made CompileModule die with an uncatchable
	// "fatal error: out of memory" while materialising the locals slice.
	typeSec := append([]byte{wasm.SectionIDType}, u32(4)...)
	typeSec = append(typeSec, 0x01, 0x60, 0x00, 0x00) // 1 type: () -> ()

	funcSec := append([]byte{wasm.SectionIDFunction}, u32(2)...)
	funcSec = append(funcSec, 0x01, 0x00) // 1 function, type 0

	// Code entry: size prefix, locals vector count = 1, one group of 0xffffffff
	// i32 locals, body "end".
	locals := []byte{0x01}
	locals = append(locals, 0xff, 0xff, 0xff, 0xff, 0x0f) // num locals = 0xffffffff
	locals = append(locals, byte(wasm.ValueTypeI32))
	locals = append(locals, 0x0b) // end
	entry := append(u32(uint32(len(locals))), locals...)
	codeSec := append([]byte{wasm.SectionIDCode}, u32(uint32(len(entry)+1))...)
	codeSec = append(codeSec, 0x01)
	codeSec = append(codeSec, entry...)

	bin := append([]byte{}, Magic...)
	bin = append(bin, version...)
	bin = append(bin, typeSec...)
	bin = append(bin, funcSec...)
	bin = append(bin, codeSec...)

	m, err := DecodeModule(bin, api.CoreFeaturesV2, 65536, false, false, false)
	require.Error(t, err)
	require.True(t, bytes.Contains([]byte(err.Error()), []byte("too many locals")))
	require.Nil(t, m)
}

func TestDecodeModule_VectorCountExceedsInputRejected(t *testing.T) {
	tests := []struct {
		name    string
		section []byte
	}{
		{
			name: "function section count",
			// Claims 0xffffffff function type indices but only has 4 bytes left.
			section: append(append([]byte{wasm.SectionIDFunction}, u32(5)...),
				0xff, 0xff, 0xff, 0xff, 0x0f),
		},
		{
			name: "table section count",
			section: append(append([]byte{wasm.SectionIDTable}, u32(5)...),
				0xff, 0xff, 0xff, 0xff, 0x0f),
		},
		{
			name: "global section count",
			section: append(append([]byte{wasm.SectionIDGlobal}, u32(5)...),
				0xff, 0xff, 0xff, 0xff, 0x0f),
		},
		{
			name: "element section count",
			section: append(append([]byte{wasm.SectionIDElement}, u32(5)...),
				0xff, 0xff, 0xff, 0xff, 0x0f),
		},
		{
			name: "code section count",
			section: append(append([]byte{wasm.SectionIDCode}, u32(5)...),
				0xff, 0xff, 0xff, 0xff, 0x0f),
		},
		{
			name: "data section count",
			section: append(append([]byte{wasm.SectionIDData}, u32(5)...),
				0xff, 0xff, 0xff, 0xff, 0x0f),
		},
	}

	for _, tt := range tests {
		tc := tt
		t.Run(tc.name, func(t *testing.T) {
			bin := append([]byte{}, Magic...)
			bin = append(bin, version...)
			bin = append(bin, tc.section...)

			_, err := DecodeModule(bin, api.CoreFeaturesV2, 65536, false, false, false)
			require.Error(t, err)
			require.True(t, bytes.Contains([]byte(err.Error()), []byte("exceeds remaining bytes")))
		})
	}
}
