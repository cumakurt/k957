package core

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReportSealRejectsPrivateKeyAndAliases(t *testing.T) {
	for _, mode := range []string{"inside", "hard-link", "copied"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			bundle := filepath.Join(root, "report")
			if err := os.Mkdir(bundle, 0700); err != nil {
				t.Fatal(err)
			}
			prefix := filepath.Join(root, "signer")
			if mode == "inside" {
				prefix = filepath.Join(bundle, "signer")
			}
			if err := Keygen(prefix); err != nil {
				t.Fatal(err)
			}
			key := prefix + ".key"
			before, err := os.ReadFile(key)
			if err != nil {
				t.Fatal(err)
			}
			alias := filepath.Join(bundle, "unlabelled-data.bin")
			if mode == "hard-link" {
				if err := os.Link(key, alias); err != nil {
					t.Skipf("filesystem does not provide hard links: %v", err)
				}
			} else if mode == "copied" {
				if err := WriteNew(alias, before); err != nil {
					t.Fatal(err)
				}
			}
			if err := WriteNew(filepath.Join(bundle, "report.html"), []byte("Synthetic report")); err != nil {
				t.Fatal(err)
			}
			if _, err := SealReport(context.Background(), bundle, key); err == nil || !strings.Contains(err.Error(), "key") {
				t.Fatalf("private key accepted in sealed bundle: %v", err)
			}
			for _, name := range []string{reportSealManifest, reportSealSignature} {
				if _, err := os.Lstat(filepath.Join(bundle, name)); !os.IsNotExist(err) {
					t.Fatalf("failed seal retained %s: %v", name, err)
				}
			}
			after, err := os.ReadFile(key)
			if err != nil || string(before) != string(after) {
				t.Fatal("original signing key changed", err)
			}
		})
	}
}
