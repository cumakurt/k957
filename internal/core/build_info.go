package core

import (
	"runtime"
	"runtime/debug"
)

// Set by the release and validation scripts from the sorted source manifest.
// A direct go build remains usable and explicitly reports unknown source identity.
var BuildSourceSHA256 = "unknown"

type BuildDetails struct {
	Developer    DeveloperDetails `json:"developer"`
	Schema       string           `json:"schema"`
	Version      string           `json:"version"`
	SourceSHA256 string           `json:"source_sha256"`
	Toolchain    string           `json:"toolchain"`
	Target       string           `json:"target"`
	Modules      []*debug.Module  `json:"modules"`
}

func BuildInfo() BuildDetails {
	details := BuildDetails{Developer: DeveloperInfo(), Schema: "k957-build/1", Version: Version, SourceSHA256: BuildSourceSHA256, Toolchain: runtime.Version(), Target: runtime.GOOS + "/" + runtime.GOARCH, Modules: []*debug.Module{}}
	if info, ok := debug.ReadBuildInfo(); ok {
		details.Modules = info.Deps
	}
	return details
}
