package wasi_snapshot_preview1_test

import (
	"io"
	"testing"

	wazero "github.com/mgilbir/andsifr"
	"github.com/mgilbir/andsifr/internal/testing/require"
	"github.com/mgilbir/andsifr/internal/wasip1"
)

type partialIO struct {
	firstN      int
	firstErr    error
	calls       int
	transferred int
}

func (p *partialIO) transfer(b []byte) (int, error) {
	p.calls++
	if p.calls > 1 {
		return -1, io.ErrClosedPipe
	}
	n := p.firstN
	if n > 0 {
		p.transferred += n
	}
	for i := 0; i < n; i++ {
		b[i] = 'a'
	}
	return n, p.firstErr
}
func (p *partialIO) Read(b []byte) (int, error) { return p.transfer(b) }
func (p *partialIO) Write(b []byte) (int, error) {
	// A writer must not modify the guest's input bytes.
	return p.transfer(make([]byte, len(b)))
}

func TestPartialIOProgress(t *testing.T) {
	for _, operation := range []string{wasip1.FdReadName, wasip1.FdWriteName} {
		for _, tc := range []struct {
			name     string
			firstN   int
			firstErr error
			wantErr  bool
		}{
			{name: "error after first iovec", firstN: 4},
			{name: "bytes and error together", firstN: 2, firstErr: io.ErrClosedPipe},
			{name: "short transfer without error", firstN: 2},
			{name: "error before any bytes", firstErr: io.ErrClosedPipe, wantErr: true},
			{name: "negative syscall result", firstN: -1, firstErr: io.ErrClosedPipe, wantErr: true},
		} {
			t.Run(operation+"/"+tc.name, func(t *testing.T) {
				stream := &partialIO{firstN: tc.firstN, firstErr: tc.firstErr}
				mod, r, _ := requireProxyModule(t, wazero.NewModuleConfig().WithStdin(stream).WithStdout(stream))
				defer r.Close(testCtx)
				mem := mod.Memory()
				require.True(t, mem.WriteUint32Le(0, 32))
				require.True(t, mem.WriteUint32Le(4, 4))
				require.True(t, mem.WriteUint32Le(8, 36))
				require.True(t, mem.WriteUint32Le(12, 4))
				require.True(t, mem.Write(32, []byte("abcdefgh")))
				require.True(t, mem.WriteUint32Le(48, 999))
				fd := uint64(0)
				if operation == wasip1.FdWriteName {
					fd = 1
				}
				res, err := mod.ExportedFunction(operation).Call(testCtx, fd, 0, 2, 48)
				require.NoError(t, err)
				count, ok := mem.ReadUint32Le(48)
				require.True(t, ok)
				require.Equal(t, max(0, tc.firstN), stream.transferred)
				if tc.wantErr {
					require.NotEqual(t, uint64(0), res[0])
					require.Equal(t, uint32(999), count)
				} else {
					require.Equal(t, uint64(0), res[0])
					require.Equal(t, uint32(tc.firstN), count)
				}
				wantCalls := 1
				if tc.firstN == 4 && tc.firstErr == nil {
					wantCalls = 2
				}
				require.Equal(t, wantCalls, stream.calls)
			})
		}
	}
}
