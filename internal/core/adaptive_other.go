//go:build !linux && !windows && !darwin

package core

import (
	"context"
	"errors"
)

func platformProcessExecutables(context.Context) ([]ExecutableReference, string, error) {
	return nil, "unavailable", errors.New("process executable discovery is unsupported on this platform")
}
