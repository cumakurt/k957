//go:build linux

package core

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestLinuxProcessPathsDeletedAndExited(t *testing.T) {
	d := t.TempDir()
	for _, pid := range []string{"11", "12", "13", "not-a-pid"} {
		os.Mkdir(filepath.Join(d, pid), 0700)
	}
	os.Symlink("/fixture/executable", filepath.Join(d, "11", "exe"))
	os.Symlink("/fixture/executable (deleted)", filepath.Join(d, "12", "exe"))
	r, e := linuxProcessExecutables(context.Background(), d)
	if e != nil || len(r) != 6 || r[0].Status != "observed" || r[2].Status != "unavailable" || r[4].Status != "unavailable" {
		t.Fatalf("%v %v", r, e)
	}
	for _, index := range []int{1, 3, 5} {
		if r[index].Kind != "executable_mapping" || r[index].Status != "unavailable" || r[index].Reason == "" {
			t.Fatalf("missing maps must have explicit unavailable references: %+v", r[index])
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := linuxProcessExecutables(ctx, d); e == nil {
		t.Fatal("cancellation ignored")
	}
}
