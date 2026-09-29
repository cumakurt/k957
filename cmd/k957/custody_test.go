package main

import (
	"encoding/json"
	"k957/internal/core"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLICustodyWorkflow(t *testing.T) {
	d := t.TempDir()
	root := filepath.Join(d, "source")
	os.Mkdir(root, 0700)
	os.WriteFile(filepath.Join(root, "data"), []byte("synthetic"), 0600)
	pkg := filepath.Join(d, "evidence.k957")
	if e := run([]string{"collect", "--root", root, "--out", pkg, "--case", "T", "--operator", "T", "--scope", "Synthetic"}); e != nil {
		t.Fatal(e)
	}
	trust := core.CustodyTrust{Schema: "k957-custody-trust/1", Keys: []core.CustodyIdentity{}}
	for _, actor := range []string{"Alice", "Bob"} {
		if e := core.Keygen(filepath.Join(d, actor)); e != nil {
			t.Fatal(e)
		}
		pub, _ := os.ReadFile(filepath.Join(d, actor+".pub"))
		trust.Keys = append(trust.Keys, core.CustodyIdentity{Actor: actor, PublicKey: strings.TrimSpace(string(pub))})
	}
	trustPath := filepath.Join(d, "trust.json")
	os.WriteFile(trustPath, core.JSON(trust), 0600)
	previous := ""
	head := ""
	for i, step := range []struct{ action, actor, to string }{{"register", "Alice", ""}, {"transfer", "Alice", "Bob"}, {"accept", "Bob", ""}} {
		out := filepath.Join(d, step.action+".json")
		args := []string{"custody", "--in", pkg, "--trust", trustPath, "--action", step.action, "--actor", step.actor, "--location", "Lab", "--note", "Synthetic", "--sign-key", filepath.Join(d, step.actor+".key"), "--out", out}
		if previous != "" {
			args = append(args, "--previous", previous, "--expected-head", head)
		}
		if step.to != "" {
			args = append(args, "--to", step.to)
		}
		if e := run(args); e != nil {
			t.Fatal(e)
		}
		if e := run(args); e == nil {
			t.Fatal("overwrote old ledger")
		}
		b, _ := os.ReadFile(out)
		var l core.CustodyLedger
		json.Unmarshal(b, &l)
		if len(l.Events) != i+1 {
			t.Fatal("missing event")
		}
		head = l.Events[i].Hash
		previous = out
	}
	if e := run([]string{"custody-verify", "--in", pkg, "--ledger", previous, "--trust", trustPath, "--expected-head", head}); e != nil {
		t.Fatal(e)
	}
	report := filepath.Join(d, "report")
	if e := run([]string{"analyze", "--in", pkg, "--custody", previous, "--custody-trust", trustPath, "--custody-head", head, "--out", report}); e != nil {
		t.Fatal(e)
	}
	a, e := core.LoadAnalysis(filepath.Join(report, "analysis.json"))
	if e != nil || a.Custody == nil || a.Custody.CurrentHolder != "Bob" {
		t.Fatalf("%+v %v", a.Custody, e)
	}
	for _, args := range [][]string{
		{"custody"}, {"custody", "--bad"}, {"custody-verify", "--in", pkg, "--ledger", previous},
		{"custody-verify", "--in", pkg, "--ledger", previous, "--trust", trustPath, "extra"},
		{"analyze", "--in", pkg, "--custody-trust", trustPath, "--out", filepath.Join(d, "bad-report")},
		{"verify", "--in", pkg, "--custody", previous},
	} {
		if e := run(args); e == nil {
			t.Fatalf("accepted %v", args)
		}
	}
}
