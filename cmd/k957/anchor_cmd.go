package main

import (
	"flag"
	"k957/internal/core"
)

func runCustodyAnchor(args []string) error {
	f := flag.NewFlagSet("custody-anchor", flag.ContinueOnError)
	ledger := f.String("ledger", "", "custody ledger")
	trust := f.String("trust", "", "external actor/key policy")
	key := f.String("sign-key", "", "independent witness Ed25519 key")
	witness := f.String("witness", "", "declared witness identifier")
	reference := f.String("reference", "", "external retention reference")
	out := f.String("out", "", "new signed anchor JSON; retain separately from evidence")
	if stop, err := parseFlags(f, args); stop || err != nil {
		return err
	}
	l, err := core.LoadCustody(*ledger)
	if err != nil {
		return err
	}
	t, err := core.LoadCustodyTrust(*trust)
	if err != nil {
		return err
	}
	a, err := core.AnchorCustody(l, t, *key, *witness, *reference)
	if err != nil {
		return err
	}
	return core.WriteJSONNew(*out, a)
}
