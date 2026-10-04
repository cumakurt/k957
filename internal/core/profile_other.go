//go:build !linux && !windows && !darwin

package core

func artifactCandidates() []string { return nil }
