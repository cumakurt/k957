//go:build linux || darwin

package core

import (
	"fmt"
	"math"
	"os"
	"syscall"
)

var statFilesystem = syscall.Statfs

func probeVolume(path string) (volumeSample, error) {
	var stat syscall.Statfs_t
	if e := statFilesystem(path, &stat); e != nil {
		return volumeSample{}, e
	}
	info, e := os.Stat(path)
	if e != nil {
		return volumeSample{}, e
	}
	dev := info.Sys().(*syscall.Stat_t)
	blocks := uint64(stat.Bavail)
	size := uint64(stat.Bsize)
	if size == 0 || blocks > math.MaxInt64/size {
		return volumeSample{}, fmt.Errorf("filesystem capacity outside supported range")
	}
	return volumeSample{ID: fmt.Sprintf("device:%v", dev.Dev), Available: int64(blocks * size)}, nil
}
