package wazero

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	goruntime "runtime"
	"sync"

	"github.com/mgilbir/andsifr/api"
	"github.com/mgilbir/andsifr/internal/filecache"
	"github.com/mgilbir/andsifr/internal/version"
	"github.com/mgilbir/andsifr/internal/wasm"
)

// CompilationCache reduces time spent compiling (Runtime.CompileModule) the same wasm module.
//
// # Notes
//
//   - This is an interface for decoupling, not third-party implementations.
//     All implementations are in wazero.
//   - Instances of this can be reused across multiple runtimes, if configured
//     via RuntimeConfig.
//   - The cache check happens before the compilation, so if multiple Goroutines are
//     trying to compile the same module simultaneously, it is possible that they
//     all compile the module. The design here is that the lock isn't held for the action "Compile"
//     but only for checking and saving the compiled result. Therefore, we strongly recommend that the embedder
//     does the centralized compilation in a single Goroutines (or multiple Goroutines per Wasm binary) to generate cache rather than
//     trying to Compile in parallel for a single module. In other words, we always recommend to produce CompiledModule
//     share it across multiple Goroutines to avoid trying to compile the same module simultaneously.
type CompilationCache interface{ api.Closer }

// NewCompilationCache returns a new CompilationCache to be passed to RuntimeConfig.
// This configures only in-memory cache, and doesn't persist to the file system. See wazero.NewCompilationCacheWithDir for detail.
//
// The returned CompilationCache can be used to share the in-memory compilation results across multiple instances of wazero.Runtime.
func NewCompilationCache() CompilationCache {
	return &cache{}
}

// NewCompilationCacheWithDir is like wazero.NewCompilationCache except the result also writes
// state into the directory specified by `dirname` parameter.
//
// If the dirname doesn't exist, this creates it or returns an error.
//
// Those running wazero as a CLI or frequently restarting a process using the same wasm should
// use this feature to reduce time waiting to compile the same module a second time.
//
// The contents written into dirname are wazero-version specific, meaning different versions of
// wazero will duplicate entries for the same input wasm.
//
// Note: The embedder must safeguard this directory from external changes.
func NewCompilationCacheWithDir(dirname string) (CompilationCache, error) {
	c := &cache{}
	err := c.ensuresFileCache(dirname, version.GetWazeroVersion())
	return c, err
}

// cache implements Cache interface.
type cache struct {
	// engs holds one engine per (engine kind, core features) pair. If the
	// cache is configured, engines are shared across multiple instances of
	// Runtime, and their lifetime is not bound to them: each engine is alive
	// until Cache.Close is called. Keying on features too prevents a second
	// Runtime with different core features from silently reusing an engine
	// compiled under the first Runtime's features (C61 in
	// codebase-audit-2026-10-18.md).
	engsMux   sync.Mutex
	engs      map[engineKey]wasm.Engine
	fileCache filecache.Cache
}

// engineKey identifies a shared engine inside a cache.
type engineKey struct {
	kind     engineKind
	features api.CoreFeatures
}

func (c *cache) initEngine(ek engineKind, ne newEngine, ctx context.Context, features api.CoreFeatures) wasm.Engine {
	key := engineKey{kind: ek, features: features}
	c.engsMux.Lock()
	defer c.engsMux.Unlock()
	if c.engs == nil {
		c.engs = make(map[engineKey]wasm.Engine)
	}
	if eng, ok := c.engs[key]; ok {
		return eng
	}
	eng := ne(ctx, features, c.fileCache)
	c.engs[key] = eng
	return eng
}

// Close implements the same method on the Cache interface.
func (c *cache) Close(_ context.Context) (err error) {
	c.engsMux.Lock()
	defer c.engsMux.Unlock()
	for _, eng := range c.engs {
		if eng != nil {
			if err = eng.Close(); err != nil {
				return
			}
		}
	}
	return
}

func (c *cache) ensuresFileCache(dir string, wazeroVersion string) error {
	// Resolve a potentially relative directory into an absolute one.
	var err error
	dir, err = filepath.Abs(dir)
	if err != nil {
		return err
	}

	// Ensure the user-supplied directory.
	if err = mkdir(dir); err != nil {
		return err
	}

	// Create a version-specific directory to avoid conflicts.
	dirname := path.Join(dir, "wazero-"+wazeroVersion+"-"+goruntime.GOARCH+"-"+goruntime.GOOS)
	if err = mkdir(dirname); err != nil {
		return err
	}

	c.fileCache = filecache.New(dirname)
	return nil
}

func mkdir(dirname string) error {
	if st, err := os.Stat(dirname); errors.Is(err, os.ErrNotExist) {
		// If the directory not found, create the cache dir.
		if err = os.MkdirAll(dirname, 0o700); err != nil {
			return fmt.Errorf("create directory %s: %v", dirname, err)
		}
	} else if err != nil {
		return err
	} else if !st.IsDir() {
		return fmt.Errorf("%s is not dir", dirname)
	}
	return nil
}
