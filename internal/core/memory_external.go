package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

type SymbolArtifact struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}
type MemoryExamination struct {
	Help          *ToolInvocation  `json:"help,omitempty"`
	Schema        string           `json:"schema"`
	ImageSHA256   string           `json:"image_sha256"`
	ImageBytes    int64            `json:"image_bytes"`
	Plugin        string           `json:"plugin"`
	Status        string           `json:"status"`
	Tool          ToolInvocation   `json:"tool"`
	Symbols       []SymbolArtifact `json:"symbols"`
	SymbolsDigest string           `json:"symbols_digest"`
	Rows          int              `json:"rows"`
	Error         string           `json:"error,omitempty"`
	Notes         []string         `json:"notes"`
}

func stageSymbols(ctx context.Context, source, dest string) (artifacts []SymbolArtifact, err error) {
	info, e := os.Lstat(source)
	if e != nil {
		return nil, e
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("symbols must be a real directory")
	}
	if e = os.Mkdir(dest, 0700); e != nil {
		return nil, e
	}
	e = filepath.WalkDir(source, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if e := ctx.Err(); e != nil {
			return e
		}
		if path == source {
			return nil
		}
		rel, e := filepath.Rel(source, path)
		if e != nil {
			return e
		}
		name := filepath.ToSlash(rel)
		if !validReportName(name) {
			return errors.New("invalid symbol path")
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("symbol symlink rejected")
		}
		target := filepath.Join(dest, rel)
		if entry.IsDir() {
			return os.Mkdir(target, 0700)
		}
		lower := strings.ToLower(name)
		if !strings.HasSuffix(lower, ".json") && !strings.HasSuffix(lower, ".json.xz") && !strings.HasSuffix(lower, ".json.gz") && !strings.HasSuffix(lower, ".zip") {
			return errors.New("symbol directory must contain JSON/compressed JSON/ZIP data only; plugin code is excluded")
		}
		sum, size, e := stageRawImage(ctx, path, target, "", 0)
		if e != nil {
			return e
		}
		artifacts = append(artifacts, SymbolArtifact{Name: name, Size: size, SHA256: sum})
		return nil
	})
	sort.Slice(artifacts, func(i, j int) bool { return artifacts[i].Name < artifacts[j].Name })
	return artifacts, e
}

func ExamineMemory(ctx context.Context, image, out, expected, tool, symbolDir, plugin string) (result MemoryExamination, err error) {
	out, e := filepath.Abs(out)
	if e != nil {
		return result, e
	}
	if !memoryPluginName(plugin) {
		return result, errors.New("invalid read-only memory plugin name")
	}
	if tool == "" || symbolDir == "" {
		return result, errors.New("Volatility executable and offline symbol directory required")
	}
	if e := os.Mkdir(out, 0700); e != nil {
		return result, e
	}
	ok := false
	defer func() {
		if !ok {
			os.RemoveAll(out)
		}
	}()
	options, _ := ctx.Value(memoryExaminationKey{}).(memoryExaminationOptions)
	dir, e := memoryStaging(image, out, options.workDir)
	if e != nil {
		return result, e
	}
	defer os.RemoveAll(dir)
	sum, size, e := stageRawImage(ctx, image, filepath.Join(dir, "memory.bin"), expected, 0)
	if e != nil {
		return result, e
	}
	symbols, e := stageSymbols(ctx, symbolDir, filepath.Join(dir, "symbols"))
	if e != nil {
		return result, e
	}
	if e = os.Mkdir(filepath.Join(dir, "cache"), 0700); e != nil {
		return result, e
	}
	args := []string{"--offline", "--parallelism", "off", "--cache-path", filepath.Join(dir, "cache"), "-s", filepath.Join(dir, "symbols"), "-o", out, "-q", "-r", "json", "-f", filepath.Join(dir, "memory.bin"), plugin}
	invocation, runErr := runDerivedTool(ctx, tool, args, dir, "objects.json", "tool.stderr", 0, 0)
	if invocation.Executable == "" {
		return result, runErr
	}
	result = MemoryExamination{Schema: "k957-memory-examination/1", ImageSHA256: sum, ImageBytes: size, Plugin: plugin, Status: "interpreted", Tool: invocation, Symbols: symbols, SymbolsDigest: digestJSON(symbols), Notes: []string{"Kernel enumeration is performed by the recorded external Volatility plugin, using private verified image/symbol copies and --offline. This does not claim an in-process k957 kernel reconstruction engine.", "The executable hash does not bind every interpreter/library module. --offline suppresses Volatility symbol downloads; complete OS network/filesystem/memory sandboxing is not asserted.", "Kernel-symbol compatibility is decided by Volatility. Missing/incompatible symbols and layer failures produce failed status; string/header observations are never substituted for kernel objects.", "Object identifiers/addresses in objects.json are scoped to this image hash and recorded plugin/symbol digest. No independent native platform/reference-image accuracy validation is implied by successful tool execution."}}
	after, e := fileSHA256Progress(filepath.Join(dir, "memory.bin"), "", 0, &verifyMeter{ctx: ctx})
	if e != nil {
		return result, e
	}
	if after != sum {
		return result, errors.New("memory tool changed staged image")
	}
	for _, symbol := range symbols {
		after, e := fileSHA256Progress(filepath.Join(dir, "symbols", filepath.FromSlash(symbol.Name)), "", 0, &verifyMeter{ctx: ctx})
		if e != nil {
			return result, e
		}
		if after != symbol.SHA256 {
			return result, errors.New("memory tool changed staged symbols")
		}
	}
	if runErr != nil {
		result.Status = "failed"
		result.Error = runErr.Error()
	} else {
		var e error
		result.Rows, e = countMemoryJSON(ctx, filepath.Join(dir, "objects.json"))
		if e != nil {
			result.Status = "failed"
			result.Error = "Invalid Volatility JSON: " + e.Error()
		}

	}
	for _, name := range []string{"objects.json", "tool.stderr"} {
		if e = copyDerivedFile(ctx, filepath.Join(dir, name), filepath.Join(out, name), ""); e != nil {
			return result, e
		}
	}
	if e = WriteJSONNew(filepath.Join(out, "memory-examination.json"), result); e != nil {
		return result, e
	}
	ok = true
	if result.Status == "failed" {
		return result, errors.New(result.Error)
	}
	return result, nil
}

var memoryPluginPattern = regexp.MustCompile(`^(?:linux|windows|mac)\.[A-Za-z0-9_.]+$`)

func memoryPluginName(name string) bool {
	return memoryPluginPattern.MatchString(name) || name == "banners.Banners" || name == "yarascan.YaraScan"
}
func countMemoryJSON(ctx context.Context, path string) (int, error) {
	f, e := os.Open(path)
	if e != nil {
		return 0, e
	}
	defer f.Close()
	d := json.NewDecoder(contextReader{ctx: ctx, r: f})
	token, e := d.Token()
	if e != nil {
		return 0, e
	}
	if token != json.Delim('[') {
		return 0, errors.New("JSON array required")
	}
	n := 0
	for d.More() {
		if e = ctx.Err(); e != nil {
			return n, e
		}
		token, e = d.Token()
		if e != nil {
			return n, e
		}
		if token != json.Delim('{') {
			return n, errors.New("JSON object row required")
		}
		if e = consumeMemoryObject(d); e != nil {
			return n, e
		}
		n++
	}

	if _, e = d.Token(); e != nil {
		return n, e
	}
	var extra any
	if e = d.Decode(&extra); e != io.EOF {
		return n, fmt.Errorf("unexpected trailing JSON")
	}
	return n, nil
}

func consumeMemoryObject(d *json.Decoder) error {
	keys := map[string]bool{}
	for d.More() {
		token, e := d.Token()
		if e != nil {
			return e
		}
		key, ok := token.(string)
		if !ok || keys[key] {
			return errors.New("duplicate memory JSON key")
		}
		keys[key] = true
		if e = consumeMemoryValue(d); e != nil {
			return e
		}
	}
	_, e := d.Token()
	return e
}
func consumeMemoryValue(d *json.Decoder) error {
	token, e := d.Token()
	if e != nil {
		return e
	}
	switch token {
	case json.Delim('{'):
		return consumeMemoryObject(d)
	case json.Delim('['):
		for d.More() {
			if e = consumeMemoryValue(d); e != nil {
				return e
			}
		}
		_, e = d.Token()
		return e
	}
	return nil
}
