//go:build !linux

package core

func restrictParserWorker() (WorkerSecurity, error) {
	return WorkerSecurity{ProcessIsolation: true, Filesystem: "private-verified-copies; no filesystem sandbox"}, nil
}
