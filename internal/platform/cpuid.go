package platform

// CpuFeatureFlags exposes methods for querying CPU capabilities
type CpuFeatureFlags uint64

const (
	// CpuFeatureAmd64SSE4_1 is the flag to query CpuFeatureFlags.Has for SSEv4.1 capabilities on amd64
	CpuFeatureAmd64SSE4_1 = 1 << iota
	// CpuFeatureAmd64BMI1 is the flag to query CpuFeatureFlags.Has for Bit Manipulation Instruction Set 1 (e.g. TZCNT) on amd64
	CpuFeatureAmd64BMI1
	// CpuExtraFeatureABM is the flag to query CpuFeatureFlags.Has for Advanced Bit Manipulation capabilities (e.g. LZCNT) on amd64
	CpuFeatureAmd64ABM
	// CpuFeatureAmd64POPCNT is the flag to query CpuFeatureFlags.Has for the
	// POPCNT instruction on amd64. The backend emits POPCNT for
	// ssa.OpcodePopcnt: SSE4.1 alone does not imply it (they are adjacent but
	// distinct CPUID bits), so CompilerSupported must gate on both (C67 in
	// codebase-audit-2026-10-18.md).
	CpuFeatureAmd64POPCNT
)

const (
	// CpuFeatureArm64Atomic is the flag to query CpuFeatureFlags.Has for Large System Extensions capabilities on arm64
	CpuFeatureArm64Atomic CpuFeatureFlags = 1 << iota
)

func (c CpuFeatureFlags) Has(f CpuFeatureFlags) bool {
	return c&f != 0
}

func (c CpuFeatureFlags) Raw() uint64 {
	return uint64(c)
}
