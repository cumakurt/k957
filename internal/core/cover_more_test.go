package core

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

type cancelAfter struct {
	context.Context
	left int
}

func (c *cancelAfter) Err() error {
	if c.left <= 0 {
		return context.Canceled
	}
	c.left--
	return nil
}

func TestCollectBranches(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	root := filepath.Join(dir, "root")
	os.Mkdir(root, 0700)
	os.WriteFile(filepath.Join(root, "a.txt"), []byte("alpha-data"), 0600)
	os.WriteFile(filepath.Join(root, "b.txt"), []byte("beta-data"), 0600)
	base := Options{Root: root, Out: filepath.Join(dir, "out.k957"), Case: "C", Operator: "O", Scope: "S", MaxFile: 1 << 20, MaxTotal: 1 << 20, MaxFiles: 10}
	if _, e := Collect(ctx, Options{EncryptionKey: "k"}); e == nil {
		t.Fatal("expected encryption error")
	}
	if _, e := Collect(ctx, Options{}); e == nil {
		t.Fatal("expected required fields")
	}
	if _, e := Collect(ctx, Options{Case: "C", Operator: "O", Scope: "S", Out: base.Out}); e == nil {
		t.Fatal("expected source requirement")
	}
	bad := base
	bad.MaxFiles = 0
	if _, e := Collect(ctx, bad); e == nil {
		t.Fatal("expected limit error")
	}
	cancelled := cancelAfter{Context: ctx, left: 0}
	if _, e := Collect(&cancelled, base); e == nil {
		t.Fatal("expected cancel")
	}
	notDir := base
	notDir.Root = filepath.Join(root, "a.txt")
	notDir.Out = filepath.Join(dir, "notdir.k957")
	if _, e := Collect(ctx, notDir); e == nil {
		t.Fatal("expected directory root")
	}
	missing := base
	missing.Root = filepath.Join(dir, "missing")
	missing.Out = filepath.Join(dir, "missing.k957")
	if _, e := Collect(ctx, missing); e == nil {
		t.Fatal("expected missing root")
	}
	broken := filepath.Join(dir, "broken")
	os.Symlink(filepath.Join(dir, "nope"), broken)
	linkOpt := base
	linkOpt.Root = ""
	linkOpt.Paths = []string{broken}
	linkOpt.Out = filepath.Join(dir, "link.k957")
	if _, e := Collect(ctx, linkOpt); e == nil {
		t.Fatal("expected symlink path error")
	}
	inside := base
	inside.Out = filepath.Join(root, "inside.k957")
	if _, e := Collect(ctx, inside); e == nil {
		t.Fatal("expected output inside source")
	}
	os.WriteFile(base.Out, []byte("x"), 0600)
	if _, e := Collect(ctx, base); e == nil {
		t.Fatal("expected existing output")
	}
	os.Remove(base.Out)

	limited := base
	limited.Out = filepath.Join(dir, "files.k957")
	limited.MaxFiles = 1
	if m, e := Collect(ctx, limited); e != nil || m.Status != "partial" {
		t.Fatal(e, m.Status)
	}
	sized := base
	sized.Out = filepath.Join(dir, "size.k957")
	sized.MaxFile = 1
	if m, e := Collect(ctx, sized); e != nil || m.Status != "partial" {
		t.Fatal(e, m.Status)
	}
	total := base
	total.Out = filepath.Join(dir, "total.k957")
	total.MaxTotal = 1
	total.MaxFile = 1 << 20
	if m, e := Collect(ctx, total); e != nil || m.Status != "partial" {
		t.Fatal(e, m.Status)
	}
	walkCtx := &cancelAfter{Context: ctx, left: 1}
	walkOpt := base
	walkOpt.Out = filepath.Join(dir, "walk.k957")
	if _, e := Collect(walkCtx, walkOpt); e == nil {
		t.Fatal("expected walk cancel")
	}
	readCtx := &cancelAfter{Context: ctx, left: 2}
	readOpt := base
	readOpt.Out = filepath.Join(dir, "read.k957")
	readOpt.Root = filepath.Join(dir, "one")
	os.Mkdir(readOpt.Root, 0700)
	os.WriteFile(filepath.Join(readOpt.Root, "a.txt"), bytes.Repeat([]byte("z"), 64), 0600)
	if _, e := Collect(readCtx, readOpt); e == nil {
		t.Fatal("expected read cancel")
	}

	if runtime.GOOS != "windows" && os.Geteuid() != 0 {
		locked := filepath.Join(dir, "locked")
		os.Mkdir(locked, 0700)
		secret := filepath.Join(locked, "secret")
		os.WriteFile(secret, []byte("secret-value"), 0000)
		t.Cleanup(func() { os.Chmod(secret, 0600) })
		lockOpt := base
		lockOpt.Root = locked
		lockOpt.Out = filepath.Join(dir, "locked.k957")
		if m, e := Collect(ctx, lockOpt); e != nil || m.Status != "partial" {
			t.Fatal(e, m.Status)
		}

	}

	skipRoot := filepath.Join(dir, "skip")
	os.Mkdir(skipRoot, 0700)
	if e := os.Symlink("a", filepath.Join(skipRoot, "link")); e != nil {
		t.Fatal(e)
	}
	var skipped []string
	skipOpt := base
	skipOpt.Root = ""
	skipOpt.Paths = []string{skipRoot}
	skipOpt.Out = filepath.Join(dir, "skip.k957")
	skipOpt.OnSkip = func(path, reason string) { skipped = append(skipped, path) }
	if _, e := Collect(ctx, skipOpt); e != nil || len(skipped) == 0 {
		t.Fatal(e, skipped)
	}
	r := &readErrorReader{r: failReader{}}
	r.Read(make([]byte, 4))
	if r.err == nil {
		t.Fatal("expected stored read error")
	}
}

func TestResumeAndWorkEdges(t *testing.T) {
	ctx := context.Background()
	if _, e := CollectResumable(ctx, Options{}, t.TempDir(), false); e == nil {
		t.Fatal("expected required fields")
	}
	d, o := fixture(t, false)
	o.MaxFile = 0
	if _, e := CollectResumable(ctx, o, filepath.Join(d, "work"), false); e == nil {
		t.Fatal("expected bad limits")
	}
	o.MaxFile = 1 << 20
	o.Root = filepath.Join(d, "missing")
	if _, e := CollectResumable(ctx, o, filepath.Join(d, "work"), false); e == nil {
		t.Fatal("expected missing root")
	}
	o.Root = filepath.Join(d, "source", "auth.log")
	if _, e := CollectResumable(ctx, o, filepath.Join(d, "work2"), false); e == nil {
		t.Fatal("expected file root")
	}
	_, o = fixture(t, false)
	o.Out = filepath.Join(o.Root, "nested.k957")
	if _, e := CollectResumable(ctx, o, filepath.Join(d, "work3"), false); e == nil {
		t.Fatal("expected overlap")
	}
	_, o = fixture(t, false)
	os.WriteFile(o.Out, []byte("x"), 0600)
	if _, e := CollectResumable(ctx, o, filepath.Join(filepath.Dir(o.Out), "work4"), false); e == nil {
		t.Fatal("expected existing output")
	}
	if _, e := InspectWork(ctx, filepath.Join(d, "missing-work"), false); e == nil {
		t.Fatal("expected missing work")
	}
	if _, e := InspectWork(ctx, filepath.Join(d, "missing-key"), false, filepath.Join(d, "no-key")); e == nil {
		t.Fatal("expected bad key")
	}
	file := filepath.Join(d, "not-work")
	os.WriteFile(file, []byte("x"), 0600)
	if _, e := InspectWork(ctx, file, false); e == nil {
		t.Fatal("expected non-directory")
	}
	empty := filepath.Join(d, "empty-work")
	os.Mkdir(empty, 0700)
	if _, e := InspectWork(ctx, empty, false); e == nil {
		t.Fatal("expected missing chunks")
	}
	if _, e := Preflight(ctx, Options{}, "", false, 0); e == nil {
		t.Fatal("expected preflight requirements")
	}
	if _, e := PreflightResume(ctx, Options{}, "", 0); e == nil {
		t.Fatal("expected resume preflight requirements")
	}
	var result PreflightResult
	if _, e := resumePreflightInventory(ctx, Options{}, o.Root, empty, &result); e == nil {
		t.Fatal("expected inventory error")
	}
}

func TestLogsCorrelateAndExports(t *testing.T) {
	if recognizedField("nope") {
		t.Fatal("unexpected field")
	}
	if _, ok := decodeRecord("[]"); ok {
		t.Fatal("expected non-object")
	}
	if _, ok := decodeRecord("{"); ok {
		t.Fatal("expected truncated object")
	}
	if _, ok := decodeRecord(`{"timestamp":1}`); ok {
		t.Fatal("expected non-string")
	}
	if _, ok := decodeRecord(`{"a":1,`); ok {
		t.Fatal("expected bad token")
	}
	long := strings.Repeat("a", 300)
	ev, ok := eventFromFields(map[string]string{"timestamp": "2026-01-02T03:04:05Z", "message": long, "user": strings.Repeat("u", 257)}, Item{}, 1, 0)
	if ok || ev.Type != "" {
		t.Fatal("expected long user rejection")
	}
	ev, ok = eventFromFields(map[string]string{"timestamp": "2026-01-02T03:04:05Z", "message": strings.Repeat("a", 500)}, Item{ID: "E1"}, 1, 0)
	if !ok || len([]rune(ev.Detail)) != 400 {
		t.Fatal(ok, len([]rune(ev.Detail)))
	}
	if _, ok = parseLogLine("   ", Item{}, 1); ok {
		t.Fatal("expected blank line")
	}
	if _, ok = parseLogLine(strings.Repeat("x", 65537), Item{}, 1); ok {
		t.Fatal("expected long line")
	}
	if _, ok = parseLogLine("{", Item{}, 1); ok {
		t.Fatal("expected bad json line")
	}

	t0 := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	t1 := t0.Add(time.Hour)
	events := []Event{{Type: "log_timestamp", User: "same", Evidence: "a", Time: t1}, {Type: "log_timestamp", User: "same", Evidence: "b", Time: t0}}
	for i := 0; i < 20000; i++ {
		events = append(events, Event{Type: "log_timestamp", User: fmt.Sprintf("user-%d", i), Evidence: "a", Time: t1})
	}
	_, notes := correlate(events)
	if !strings.Contains(strings.Join(notes, " "), "20,000") {
		t.Fatal("expected limit note")
	}

	dir := t.TempDir()
	blocked := filepath.Join(dir, "blocked")
	os.WriteFile(blocked, []byte("x"), 0600)
	if e := sharedCSV(filepath.Join(blocked, "x.csv"), []string{"h"}, [][]string{{"a"}}); e == nil {
		t.Fatal("expected csv path error")
	}
	if e := exportNetwork(Analysis{NetworkFlows: []NetworkFlow{{Evidence: "E", Protocol: "TCP"}}}, blocked); e == nil {
		t.Fatal("expected network export error")
	}
	if e := exportMemory(Analysis{Memories: []MemoryAnalysis{{Evidence: "M", Hits: []MemoryHit{{Rule: "r"}}}}}, blocked); e == nil {
		t.Fatal("expected memory export error")
	}
	memDir := filepath.Join(dir, "mem")
	os.Mkdir(memDir, 0700)
	os.Mkdir(filepath.Join(memDir, "memory-hits.csv"), 0700)
	if e := exportMemory(Analysis{Memories: []MemoryAnalysis{{Hits: []MemoryHit{{Rule: "r", Excerpt: "x"}}}}}, memDir); e == nil {
		t.Fatal("expected hits export error")
	}
	emptyHits := filepath.Join(dir, "empty-hits")
	os.Mkdir(emptyHits, 0700)
	if e := exportMemory(Analysis{Memories: []MemoryAnalysis{{Evidence: "M"}}}, emptyHits); e != nil {
		t.Fatal(e)
	}
	if e := exportCustodyCSV(&CustodyStatus{Events: []CustodyClaim{{Action: "transfer"}}}, filepath.Join(blocked, "c.csv")); e == nil {
		t.Fatal("expected custody export error")
	}
	var when time.Time
	if sharedTime(nil) != "" || sharedTime(&t0) == "" || sharedTime(&when) == "" {
		t.Fatal("shared time")
	}
	if e := ExportShared(SharedReport{}, filepath.Join(dir, "share")); e == nil {
		t.Fatal("expected invalid shared report")
	}
	shareDir := filepath.Join(dir, "share-out")
	os.Mkdir(shareDir, 0700)
	if e := ExportShared(SharedReport{Schema: shareSchema, Version: Version, Policy: SharedPolicySummary{FreeTextOmitted: true}}, shareDir); e == nil {
		t.Fatal("expected existing directory")
	}
}

func TestMemoryScanBranches(t *testing.T) {
	var zbuf bytes.Buffer
	zw := zip.NewWriter(&zbuf)
	entry, e := zw.Create("memory.bin")
	if e != nil {
		t.Fatal(e)
	}
	entry.Write([]byte("nope"))
	if e = zw.Close(); e != nil {
		t.Fatal(e)
	}
	zr, e := zip.NewReader(bytes.NewReader(zbuf.Bytes()), int64(zbuf.Len()))
	if e != nil {
		t.Fatal(e)
	}
	zr.File[0].Method = 99
	if limeCandidate(zr.File[0], "memory.bin") {
		t.Fatal("expected unreadable zip entry")
	}
	if _, e := scanPackageMemory(zr.File[0], Item{}, nil); e == nil {
		t.Fatal("expected open error")
	}
	if _, e := scanMemoryFile(filepath.Join(t.TempDir(), "missing"), nil); e == nil {
		t.Fatal("expected missing image")
	}
	if _, e := scanMemory(failReader{}, nil); e == nil {
		t.Fatal("expected read error")
	}
	if _, e := scanRaw(strings.NewReader(""), nil); e == nil {
		t.Fatal("expected empty raw")
	}
	if _, e := scanRaw(io.MultiReader(strings.NewReader("abc"), failReader{}), nil); e == nil {
		t.Fatal("expected raw read error")
	}
	oldWindow := memoryWindow
	memoryWindow = 4
	t.Cleanup(func() { memoryWindow = oldWindow })
	raw, e := scanRaw(strings.NewReader("Linux version 1.2.3\nhttp://one.example/a https://two.example/b "), []Rule{{ID: "pw", Contains: "password"}, {ID: "", Contains: ""}, {ID: "long", Contains: strings.Repeat("z", 4097)}})
	if e != nil || raw.Format != "raw" || raw.KernelBanner == "" {
		t.Fatal(e, raw.Format, raw.KernelBanner)
	}
	for _, osName := range []string{"windows", "darwin", "freebsd"} {
		if len(volatilityCommands("lime", "mem.lime", osName, "1.2.3")) == 0 {
			t.Fatal(osName)
		}
	}
	needle := []byte("password")
	buf := bytes.Repeat(needle, 30)
	limited, e := scanRaw(bytes.NewReader(buf), []Rule{{ID: "pw", Contains: "password"}})
	if e != nil || limited.Limited || len(limited.Hits) != 30 {
		t.Fatal(e, limited.Limited, len(limited.Hits))
	}
	many := bytes.Repeat([]byte("x"), 600)
	capped, e := scanRaw(bytes.NewReader(many), []Rule{{ID: "x", Contains: "x"}})
	if e != nil || len(capped.Hits) != 600 || capped.Limited {
		t.Fatal(e, len(capped.Hits))
	}
	s := newMemScan(nil)
	s.overlap = 0
	s.push(0, []byte("abc"))
	s.push(3, nil)
	s.addHit(preparedRule{id: "r"}, 1, "ascii", "excerpt")
	s.addHit(preparedRule{id: "r"}, 1, "ascii", "excerpt")
	if len(s.hits) != 1 {
		t.Fatal("expected dedup")
	}
	bad := []byte{'p', 'w', 0xff, 0xfe}
	if !strings.Contains(excerptAt(bad, 0, 2), ".") && excerptAt(bad, 0, 2) == "" {
		t.Fatal("expected invalid utf-8 excerpt")
	}
	if excerptAt([]byte("ok\x01value"), 0, 2) == "" {
		t.Fatal("expected control-character excerpt")
	}
	if findBanner([]byte("linux version \xff")) != "" {
		t.Fatal("expected rejected banner")
	}
	if got := findBanner([]byte("linux version Literal notes\x00Linux version 6.1.0-k957\n")); got != "Linux version 6.1.0-k957" {
		t.Fatalf("banner %q", got)
	}
	urls := newMemScan(nil)
	var b strings.Builder
	for i := 0; i < memoryURLLimit+2; i++ {
		fmt.Fprintf(&b, "http://host%d.example/x ", i)
	}
	b.WriteString("http://host0.example/x ")
	urls.collectURLs([]byte(b.String()))
	if len(urls.urls) != memoryURLLimit+2 {
		t.Fatal(len(urls.urls))
	}
	if indexUTF16Fold([]byte{1}, []byte{1}) != -1 || indexUTF16Fold([]byte{1, 0, 2, 0}, []byte{1, 0, 3}) != -1 {
		t.Fatal("expected utf16 rejection")
	}
	if !matchUTF16Fold([]byte{'A', 0}, []byte{'a', 0}) || matchUTF16Fold([]byte{'A', 1}, []byte{'a', 0}) {
		t.Fatal("utf16 fold")
	}
	var analysis Analysis
	addMemoryFindings(&analysis, MemoryAnalysis{Hits: []MemoryHit{{Rule: "r", Excerpt: strings.Repeat("e", 500)}}})
	analysis.Findings = make([]Finding, 10000)
	addMemoryFindings(&analysis, MemoryAnalysis{Hits: []MemoryHit{{Rule: "r"}}})
	rememberMemory(&analysis, MemoryAnalysis{Hits: []MemoryHit{{Rule: "r"}}})
	rememberMemory(&analysis, MemoryAnalysis{})
	annotateMemory(nil, nil)
	annotateMemory(&MemoryAnalysis{}, &MemoryRecord{Format: "lime", Image: "memory.lime", OS: "linux", KernelRelease: "9", Ranges: []MemoryRange{{UnreadablePages: 2}}, SHA256: "abc"})
	hdr := make([]byte, limeHeaderSize)
	binary.LittleEndian.PutUint32(hdr[0:4], limeMagic)
	binary.LittleEndian.PutUint32(hdr[4:8], limeVersion)
	var img bytes.Buffer
	for i := 0; i < 100001; i++ {
		img.Write(hdr)
		img.WriteByte(0)
	}
	if m, e := scanLime(&img, nil); e != nil || m.Ranges != 100001 {
		t.Fatal("unexpected range limit", e, m.Ranges)
	}
}

func TestEasyRemainingBranches(t *testing.T) {
	t0 := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	events := []Event{
		{Type: "log_timestamp", User: "b", Evidence: "a", Time: t0},
		{Type: "log_timestamp", User: "b", Evidence: "b", Time: t0},
		{Type: "log_timestamp", User: "a", Evidence: "a", Time: t0},
		{Type: "log_timestamp", User: "a", Evidence: "c", Time: t0},
	}
	out, _ := correlate(events)
	if len(out) < 2 || out[0].Value > out[1].Value {
		t.Fatalf("%+v", out)
	}
	if _, ok := decodeRecord(`{"timestamp":`); ok {
		t.Fatal("expected raw decode failure")
	}
	key := filepath.Join(t.TempDir(), "short")
	os.WriteFile(key, []byte("aa\n"), 0600)
	if _, e := newWorkCrypto(key); e == nil {
		t.Fatal("expected short stage key")
	}
	d, o := fixture(t, false)
	work := filepath.Join(d, "work")
	if _, e := CollectResumable(context.Background(), o, work, false); e != nil {
		t.Fatal(e)
	}
	ctx := &cancelAfter{Context: context.Background(), left: 0}
	if _, e := InspectWork(ctx, work, false); e == nil {
		t.Fatal("expected cancelled inspection")
	}
	if st, e := InspectWork(context.Background(), work, false); e != nil || st.Completed == 0 {
		t.Fatal(e, st.Completed)
	}
	broken := filepath.Join(d, "broken-root")
	os.Symlink(filepath.Join(d, "missing-root"), broken)
	if _, e := Preflight(context.Background(), Options{Root: broken, Out: filepath.Join(d, "out.k957"), MaxFile: 100, MaxTotal: 100, MaxFiles: 10}, "", false, 0); e == nil {
		t.Fatal("expected symlink root")
	}
	n := 0
	_, e := preflight(context.Background(), Options{Root: o.Root, Out: filepath.Join(d, "planned.k957"), MaxFile: 1 << 20, MaxTotal: 1 << 20, MaxFiles: 10}, filepath.Join(d, "plan-work"), false, 0, func(path string) (volumeSample, error) {
		n++
		return volumeSample{ID: "fs", Available: int64(1000 - n*10)}, nil
	})
	if e != nil {
		t.Fatal(e)
	}
}

func TestMemoryScanKeepsIndexesOnBinaryData(t *testing.T) {
	// 0xFF is invalid UTF-8. bytes.ToLower turns each one into U+FFFD, so the
	// lowercased copy is longer than the image and its indexes must not be used.
	body := append(bytes.Repeat([]byte{0xFF}, 400), []byte("Linux Version 9.9.9-k957\nhttps://Example.TEST/a marker\n")...)
	got, e := scanRaw(bytes.NewReader(body), []Rule{{ID: "marker", Description: "marker", Contains: "Marker"}})
	if e != nil {
		t.Fatal(e)
	}
	if got.KernelBanner != "Linux Version 9.9.9-k957" {
		t.Fatalf("banner %q", got.KernelBanner)
	}
	if len(got.URLs) != 1 || got.URLs[0] != "https://Example.TEST/a" {
		t.Fatalf("urls %#v", got.URLs)
	}
	if len(got.Hits) != 1 || got.Hits[0].Rule != "marker" {
		t.Fatalf("hits %#v", got.Hits)
	}
	if excerptAt(body, len(body)+1, 1) != "" {
		t.Fatal("expected empty excerpt past the image")
	}
}
