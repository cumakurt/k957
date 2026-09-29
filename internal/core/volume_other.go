//go:build !linux && !darwin && !windows

package core

import "errors"

func probeVolume(path string) (volumeSample, error) {
	return volumeSample{}, errors.New("filesystem capacity probe not implemented on this OS")
}
