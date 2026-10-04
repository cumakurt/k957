package core

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

type MemorySuite struct {
	RecordSHA256  string       `json:"record_sha256,omitempty"`
	Files         []ReportFile `json:"files,omitempty"`
	Directory     string       `json:"directory,omitempty"`
	path          string
	Schema        string              `json:"schema"`
	ImageSHA256   string              `json:"image_sha256"`
	ImageBytes    int64               `json:"image_bytes"`
	Platform      string              `json:"platform"`
	Status        string              `json:"status"`
	Discovery     ToolInvocation      `json:"discovery"`
	Symbols       []SymbolArtifact    `json:"symbols"`
	SymbolsDigest string              `json:"symbols_digest"`
	Examinations  []MemoryExamination `json:"examinations"`
	Unavailable   []string            `json:"unavailable_plugins,omitempty"`
	Notes         []string            `json:"notes"`
}

var discoveredMemoryPlugin = regexp.MustCompile(`(?m)^\s+((?:linux|windows|mac)\.[A-Za-z0-9_.]+|banners\.Banners|yarascan\.YaraScan)\s`)
var unavailableMemoryPlugin = regexp.MustCompile(`volatility3\.plugins\.([A-Za-z0-9_.]+)`)

// ExamineMemorySuite discovers installed platform plugins, runs each independently,
// and retains successful and failed receipts. Private image staging is performed
// once. No automatic image, result-count, output-size or wall-time cap applies.
func ExamineMemorySuite(ctx context.Context, image, out, expected, tool, symbolDir, platform, workDir string) (suite MemorySuite, err error) {
	out, e := filepath.Abs(out)
	if e != nil {
		return suite, e
	}
	if platform == "darwin" {
		platform = "mac"
	}
	if platform != "linux" && platform != "windows" && platform != "mac" {
		return suite, errors.New("memory platform must be linux, windows or mac")
	}
	if tool == "" || symbolDir == "" {
		return suite, errors.New("Volatility executable and offline symbols required")
	}
	if e := os.Mkdir(out, 0700); e != nil {
		return suite, e
	}
	good := false
	defer func() {
		if !good {
			os.RemoveAll(out)
		}
	}()
	// A small tmpfs must not prevent analysis when the output filesystem has space.
	staging, e := memoryStaging(image, out, workDir)
	if e != nil {
		return suite, e
	}
	defer os.RemoveAll(staging)
	sum, size, e := stageRawImage(ctx, image, filepath.Join(staging, "memory.bin"), expected, 0)
	if e != nil {
		return suite, e
	}
	symbols, e := stageSymbols(ctx, symbolDir, filepath.Join(staging, "symbols"))
	if e != nil {
		return suite, e
	}
	if e = os.Mkdir(filepath.Join(staging, "cache"), 0700); e != nil {
		return suite, e
	}
	discovery, e := runDerivedTool(ctx, tool, []string{"--help"}, out, "plugins.txt", "discovery.stderr", 0, 0)
	if e != nil {
		return suite, e
	}
	// The help inventory is tiny relative to RAM; stream lines rather than imposing a size cap.
	names, e := memoryPluginsFromHelp(filepath.Join(out, "plugins.txt"), platform)
	if e != nil {
		return suite, e
	}
	if len(names) == 0 {
		return suite, errors.New("installed Volatility exposed no matching platform analysis plugins")
	}
	suite = MemorySuite{Schema: "k957-memory-suite/1", ImageSHA256: sum, ImageBytes: size, Platform: platform, Status: "complete", Discovery: discovery, Symbols: symbols, SymbolsDigest: digestJSON(symbols), Notes: []string{
		"Every discovered platform plugin and banners.Banners is attempted. Advertised --dump and --threads boolean options are enabled to retain recoverable process bytes and thread records. Selectors, YARA rules and other required arguments are not invented; plugins requiring these retain failed receipts. The full help inventory records unavailable optional modules.",
		"The full private image and symbol files are hash-checked after the suite. Installed tools and their dependencies must be trusted. No complete OS sandbox or independent kernel-object accuracy assurance is asserted.",
		"No automatic image-size, row-count, tool-output or runtime limit applies. Cancellation, disk exhaustion and malformed output are explicit failures. JSON row counts count top-level renderer records; nested objects remain in objects.json.",
	}}
	suite.Unavailable, e = memoryUnavailablePlugins(filepath.Join(out, "plugins.txt"), platform)
	if e != nil {
		return suite, e
	}
	if len(suite.Unavailable) > 0 {
		suite.Status = "partial"
	}
	for i, name := range names {
		if e = ctx.Err(); e != nil {
			return suite, e
		}
		ReportProgress(ctx, Progress{Phase: "memory", Detail: name, Step: i, Steps: len(names)})
		resultDir := filepath.Join(out, name)
		if e = os.Mkdir(resultDir, 0700); e != nil {
			return suite, e
		}
		args := []string{"--offline", "--parallelism", "off", "--cache-path", filepath.Join(staging, "cache"), "-s", filepath.Join(staging, "symbols"), "-o", resultDir, "-q", "-r", "json", "-f", filepath.Join(staging, "memory.bin"), name}
		help, helpErr := runDerivedTool(ctx, tool, []string{name, "--help"}, resultDir, "help.txt", "help.stderr", 0, 0)
		if helpErr == nil {
			flags, e := memoryBooleanOptions(filepath.Join(resultDir, "help.txt"))
			if e != nil {
				return suite, e
			}
			args = append(args, flags...)
		}
		invocation, runErr := runDerivedTool(ctx, tool, args, resultDir, "objects.json", "tool.stderr", 0, 0)
		r := MemoryExamination{Schema: "k957-memory-examination/1", ImageSHA256: sum, ImageBytes: size, Plugin: name, Status: "interpreted", Tool: invocation, Help: &help, SymbolsDigest: suite.SymbolsDigest}
		if runErr == nil {
			r.Rows, runErr = countMemoryJSON(ctx, filepath.Join(resultDir, "objects.json"))
		}
		if runErr != nil {
			r.Status = "failed"
			r.Error = runErr.Error()
			suite.Status = "partial"
		}
		if e = WriteJSONNew(filepath.Join(resultDir, "memory-examination.json"), r); e != nil {
			return suite, e
		}
		suite.Examinations = append(suite.Examinations, r)
	}
	after, e := fileSHA256Progress(filepath.Join(staging, "memory.bin"), "", 0, &verifyMeter{ctx: ctx})
	if e != nil {
		return suite, e
	}
	if after != sum {
		return suite, errors.New("memory suite changed its private image")
	}
	for _, s := range symbols {
		after, e = fileSHA256Progress(filepath.Join(staging, "symbols", filepath.FromSlash(s.Name)), "", 0, &verifyMeter{ctx: ctx})
		if e != nil {
			return suite, e
		}
		if after != s.SHA256 {
			return suite, errors.New("memory suite changed private symbols")
		}
	}
	suite.Files, e = reportFilesExcept(ctx, out, staging)
	if e != nil {
		return suite, e
	}
	if e = WriteJSONNew(filepath.Join(out, "memory-suite.json"), suite); e != nil {
		return suite, e
	}
	suite.RecordSHA256, e = fileSHA256Progress(filepath.Join(out, "memory-suite.json"), "", 0, &verifyMeter{ctx: ctx})
	if e != nil {
		return suite, e
	}
	good = true
	if suite.Status != "complete" {
		return suite, fmt.Errorf("memory suite retained %d plugin receipts; one or more plugins failed", len(suite.Examinations))
	}
	return suite, nil
}

func memoryBooleanOptions(path string) ([]string, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	r := bufio.NewReader(f)
	set := map[string]bool{}
	for {
		line, e := r.ReadString('\n')
		fields := strings.Fields(line)
		if len(fields) > 1 && (fields[0] == "--dump" || fields[0] == "--threads") && !strings.HasPrefix(fields[1], "[") && fields[1] != strings.ToUpper(fields[1]) {
			set[fields[0]] = true
		}
		if e == io.EOF {
			break
		}
		if e != nil {
			return nil, e
		}
	}
	flags := []string{}
	for _, name := range []string{"--dump", "--threads"} {
		if set[name] {
			flags = append(flags, name)
		}
	}
	return flags, nil
}

func memoryPluginsFromHelp(path, platform string) ([]string, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	r := bufio.NewReader(f)
	set := map[string]bool{}
	for {
		line, e := r.ReadString('\n')
		for _, m := range discoveredMemoryPlugin.FindAllStringSubmatch(line, -1) {
			if strings.HasPrefix(m[1], platform+".") || m[1] == "banners.Banners" || m[1] == "yarascan.YaraScan" {
				set[m[1]] = true
			}
		}
		if e == io.EOF {
			break
		}
		if e != nil {
			return nil, e
		}
	}
	names := make([]string, 0, len(set))
	for name := range set {
		names = append(names, name)
	}
	sort.Strings(names)
	return names, nil
}

func memoryUnavailablePlugins(path, platform string) ([]string, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	r := bufio.NewReader(f)
	set := map[string]bool{}
	for {
		line, e := r.ReadString('\n')
		for _, m := range unavailableMemoryPlugin.FindAllStringSubmatch(line, -1) {
			if strings.HasPrefix(m[1], platform+".") || m[1] == "yarascan" {
				set[m[1]] = true
			}
		}
		if e == io.EOF {
			break
		}
		if e != nil {
			return nil, e
		}
	}
	names := []string{}
	for name := range set {
		names = append(names, name)
	}
	sort.Strings(names)
	return names, nil
}

func memoryStaging(image, out, workDir string) (string, error) {
	info, e := os.Lstat(image)
	if e != nil {
		return "", e
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("memory image must be a regular file without symlinks")
	}
	candidates := []string{workDir}
	if workDir == "" {
		candidates = []string{os.TempDir(), filepath.Dir(out)}
	}
	for _, candidate := range candidates {
		sample, e := probeVolume(candidate)
		if e != nil || sample.Available < info.Size() {
			continue
		}
		if staging, e := os.MkdirTemp(candidate, "k957-memory-staging-"); e == nil {
			return staging, nil
		}
	}
	return "", errors.New("no staging filesystem has enough available space for the full memory image; choose --work-dir")
}

type memoryExaminationKey struct{}
type memoryExaminationOptions struct{ tool, symbols, workDir string }

func WithMemoryExamination(ctx context.Context, tool, symbols, workDir string) context.Context {
	return context.WithValue(ctx, memoryExaminationKey{}, memoryExaminationOptions{tool, symbols, workDir})
}
func examineConfiguredMemory(ctx context.Context, image, platform string, m *MemoryAnalysis) error {
	options, _ := ctx.Value(memoryExaminationKey{}).(memoryExaminationOptions)
	workspace, _ := ctx.Value(memoryWorkspaceKey{}).(string)
	if options.tool == "" || options.symbols == "" || workspace == "" {
		m.Notes = append(m.Notes, "Kernel examination not run: configure K957_VOLATILITY and K957_MEMORY_SYMBOLS, or run memory-examine with a trusted executable and matching offline symbols. No kernel-object conclusion is available.")
		return nil
	}
	name := "memory-kernel-" + ID()
	out := filepath.Join(workspace, name)
	suite, e := ExamineMemorySuite(ctx, image, out, m.SHA256, options.tool, options.symbols, platform, options.workDir)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if suite.Schema == "" {
		m.Notes = append(m.Notes, "Kernel examination unavailable: "+e.Error())
		return nil
	}
	suite.Directory = name
	suite.path = out
	m.Kernel = &suite
	if e != nil {
		m.Notes = append(m.Notes, "Kernel examination is partial. Inspect every plugin receipt and diagnostic.")
	}
	return nil
}
func exportMemoryKernel(ctx context.Context, a Analysis, out string) error {
	for _, m := range a.Memories {
		if m.Kernel == nil || m.Kernel.path == "" {
			continue
		}
		suite := m.Kernel
		hashes := map[string]string{}
		for _, file := range suite.Files {
			hashes[file.Name] = file.SHA256
		}
		if filepath.Base(suite.Directory) != suite.Directory || !validReportName(suite.Directory) {
			return errors.New("invalid kernel report path")
		}
		target := filepath.Join(out, suite.Directory)
		if e := os.Mkdir(target, 0700); e != nil {
			return e
		}
		e := filepath.WalkDir(suite.path, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if path == suite.path {
				return nil
			}
			rel, err := filepath.Rel(suite.path, path)
			if err != nil {
				return err
			}
			if !validReportName(filepath.ToSlash(rel)) || entry.Type()&os.ModeSymlink != 0 {
				return errors.New("unsafe memory plugin output")
			}
			dest := filepath.Join(target, rel)
			if entry.IsDir() {
				return os.Mkdir(dest, 0700)
			}
			info, err := entry.Info()
			if err != nil {
				return err
			}
			if !info.Mode().IsRegular() {
				return errors.New("special file in memory plugin output")
			}
			expected := hashes[filepath.ToSlash(rel)]
			if expected == "" && filepath.ToSlash(rel) == "memory-suite.json" {
				expected = suite.RecordSHA256
			}
			if expected == "" {
				return errors.New("unrecorded memory suite output")
			}
			return copyDerivedFile(ctx, path, dest, expected)
		})
		if e != nil {
			return e
		}
	}
	return nil
}
