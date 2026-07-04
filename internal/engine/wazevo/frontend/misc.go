package frontend

import (
	"github.com/mgilbir/andsifr/internal/engine/wazevo/ssa"
	"github.com/mgilbir/andsifr/internal/wasm"
)

func FunctionIndexToFuncRef(idx wasm.Index) ssa.FuncRef {
	return ssa.FuncRef(idx)
}
