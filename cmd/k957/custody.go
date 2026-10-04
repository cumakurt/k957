package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"k957/internal/core"
	"os"
	"time"
)

func runCustody(args []string) error {
	f := flag.NewFlagSet(args[0], flag.ContinueOnError)
	in := f.String("in", "", "verified plaintext .k957 evidence package")
	pub := f.String("trusted-key", "", "trusted evidence package signing key")
	trustPath := f.String("trust", "", "required external actor/public-key trust JSON")
	anchorPath := f.String("anchor", "", "externally retained signed custody head; custody-verify")
	anchorKey := f.String("anchor-key", "", "required external witness public key for --anchor")
	head := f.String("expected-head", "", "independently retained previous/current custody head")
	var ledgerPath, previous, out, key, at string
	var r core.CustodyRequest
	if args[0] == "custody" {
		f.StringVar(&previous, "previous", "", "previous custody ledger; omitted for register")
		f.StringVar(&out, "out", "", "new custody ledger JSON")
		f.StringVar(&key, "sign-key", "", "required actor Ed25519 private key")
		f.StringVar(&r.Action, "action", "", "register, transfer, accept, cancel or note")
		f.StringVar(&r.Actor, "actor", "", "exact actor identifier in trust list")
		f.StringVar(&r.To, "to", "", "recipient for transfer only")
		f.StringVar(&r.Location, "location", "", "declared storage/handover location")
		f.StringVar(&r.Note, "note", "", "required reason or observation")
		f.StringVar(&at, "at", "", "declared RFC3339 event time; defaults to now")
	} else {
		f.StringVar(&ledgerPath, "ledger", "", "custody ledger JSON to verify")
	}
	if stop, e := parseFlags(f, args[1:]); stop || e != nil {
		return e
	}
	if f.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments")
	}
	trust, e := core.LoadCustodyTrust(*trustPath)
	if e != nil {
		return e
	}
	p, e := core.Open(*in, *pub)
	if e != nil {
		return e
	}
	defer p.Zip.Close()
	if args[0] == "custody-verify" {
		l, e := core.LoadCustody(ledgerPath)
		if e != nil {
			return e
		}
		if *anchorPath != "" {
			anchor, e := core.LoadCustodyAnchor(*anchorPath)
			if e != nil {
				return e
			}
			claim, e := core.VerifyCustodyAnchor(anchor, l, trust, *anchorKey)
			if e != nil {
				return e
			}
			if *head != "" && *head != claim.Head {
				return fmt.Errorf("anchor and expected-head differ")
			}
			*head = claim.Head
		}
		status, e := core.ValidateCustody(l, p.ManifestSHA256, p.Manifest.ID, p.Manifest.Case, trust, *head)
		if e != nil {
			return e
		}
		return json.NewEncoder(os.Stdout).Encode(status)
	}
	if out == "" || key == "" {
		return fmt.Errorf("out and sign-key are required")
	}
	if at != "" {
		r.OccurredAt, e = time.Parse(time.RFC3339Nano, at)
		if e != nil {
			return e
		}
	}
	var prev *core.CustodyLedger
	if previous != "" {
		l, e := core.LoadCustody(previous)
		if e != nil {
			return e
		}
		prev = &l
	}
	l, e := core.AddCustody(p, prev, r, key, trust, *head)
	if e != nil {
		return e
	}
	if e = core.WriteJSONNew(out, l); e != nil {
		return e
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"out": out, "events": len(l.Events), "head": l.Events[len(l.Events)-1].Hash})
}
