//go:build windows

package core

import (
	"fmt"
	"math"
	"syscall"
	"unsafe"
)

var kernel = syscall.NewLazyDLL("kernel32.dll")
var freeSpaceEx = kernel.NewProc("GetDiskFreeSpaceExW")
var volumePath = kernel.NewProc("GetVolumePathNameW")
var volumeName = kernel.NewProc("GetVolumeNameForVolumeMountPointW")

func probeVolume(path string) (volumeSample, error) {
	p, e := syscall.UTF16PtrFromString(path)
	if e != nil {
		return volumeSample{}, e
	}
	var available uint64
	r, _, callErr := freeSpaceEx.Call(uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&available)), 0, 0)
	if r == 0 {
		return volumeSample{}, fmt.Errorf("GetDiskFreeSpaceExW: %v", callErr)
	}
	if available > math.MaxInt64 {
		return volumeSample{}, fmt.Errorf("filesystem capacity outside supported range")
	}
	root := make([]uint16, 32768)
	r, _, callErr = volumePath.Call(uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&root[0])), uintptr(len(root)))
	if r == 0 {
		return volumeSample{}, fmt.Errorf("GetVolumePathNameW: %v", callErr)
	}
	name := make([]uint16, 128)
	r, _, callErr = volumeName.Call(uintptr(unsafe.Pointer(&root[0])), uintptr(unsafe.Pointer(&name[0])), uintptr(len(name)))
	if r == 0 {
		return volumeSample{}, fmt.Errorf("volume identity unavailable: %v", callErr)
	}
	return volumeSample{ID: syscall.UTF16ToString(name), Available: int64(available)}, nil
}
