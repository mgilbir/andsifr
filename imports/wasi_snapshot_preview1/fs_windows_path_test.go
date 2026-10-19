package wasi_snapshot_preview1

import (
	"testing"

	"github.com/mgilbir/andsifr/internal/testing/require"
)

// Test_windowsPathNeedsEscape covers the platform-independent core of
// pathEscapesOnWindows: paths already accepted by fs.ValidPath that can
// nevertheless escape a pre-open root or address a device on Windows (C16 in
// codebase-audit-2026-10-18.md).
func Test_windowsPathNeedsEscape(t *testing.T) {
	tests := []struct {
		path     string
		expected bool
	}{
		{"foo.txt", false},
		{"dir/foo.txt", false},
		{"dir/sub-dir/foo.txt", false},
		// Backslash is a path separator on Windows: fs.ValidPath cannot see it.
		{`..\..\Windows\win.ini`, true},
		{`dir\..\..\secret`, true},
		{`foo\bar`, true},
		// Drive letters and NTFS alternate data streams.
		{`C:/Windows/win.ini`, true},
		{"foo.txt:stream", true},
		// DOS device names are reserved in every directory.
		{"CON", true},
		{"NUL", true},
		{"con.txt", true},
		{"COM1", true},
		{"lpt4", true},
		{"dir/CON", true},
		{"console", false},
		{"nocon", false},
		{"auxiliary", false},
	}

	for _, tt := range tests {
		tc := tt
		t.Run(tc.path, func(t *testing.T) {
			require.Equal(t, tc.expected, windowsPathNeedsEscape(tc.path))
		})
	}
}
