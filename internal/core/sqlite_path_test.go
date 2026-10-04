package core

import (
	"net/url"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestSQLiteFileURLPreservesAbsolutePath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "space # query?.sqlite")
	if runtime.GOOS == "windows" {
		path = filepath.Join(t.TempDir(), "space # unicode-é.sqlite")
	}
	u := sqliteFileURL(path)
	parsed, err := url.Parse(u.String())
	if err != nil || parsed.Host != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		t.Fatalf("invalid SQLite URI: %s %v", u.String(), err)
	}
	want := filepath.ToSlash(path)
	if !strings.HasPrefix(want, "/") {
		want = "/" + want
	}
	if parsed.Path != want {
		t.Fatalf("path changed: %q != %q", parsed.Path, want)
	}
}
