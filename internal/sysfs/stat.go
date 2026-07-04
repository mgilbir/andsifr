package sysfs

import (
	"io/fs"

	experimentalsys "github.com/mgilbir/andsifr/experimental/sys"
	"github.com/mgilbir/andsifr/sys"
)

func defaultStatFile(f fs.File) (sys.Stat_t, experimentalsys.Errno) {
	if info, err := f.Stat(); err != nil {
		return sys.Stat_t{}, experimentalsys.UnwrapOSError(err)
	} else {
		return sys.NewStat_t(info), 0
	}
}
